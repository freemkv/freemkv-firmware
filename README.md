# freemkv-flash

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14740/badge)](https://www.bestpractices.dev/projects/14740)

> **BETA: use at your own risk.** Hardware validation is limited. A complete
> MediaTek cycle has been exercised on an LG BU40N (rev 1.03). Reported Pioneer
> failures motivated the experimental Recovery workflow; recovery of the
> affected drive is not yet hardware-verified. Flashing can permanently disable
> a drive. Provided without warranty.

Standalone, multi-OS optical-drive firmware backup and flasher for freemkv,
written in Rust with native SCSI transport adapters. It issues firmware-write
commands, so read the Safety section before using `flash`.

This workspace builds two tools, each with a CLI and a desktop app:

- `freemkv-flash` (crate `freemkv-flash`, desktop app `freemkv-flash-gui`): info,
  backup, dump, flash and recovery. The crate was renamed from `freemkv-firmware`;
  the repo directory keeps the old name.
- `freemkv-fw` (desktop app `freemkv-fw-gui`): firmware authoring ("Modify").
  See [Modify](#modify-freemkv-fw).

The desktop app has Drive info, Backup, Dump, Flash, Recovery, Inspect and
Compare, and runs on macOS, Windows and Linux. See also the
[freemkv-flash crate README](crates/freemkv-flash/README.md).

## Commands

| Invocation | Writes? | Behavior |
|---|---|---|
| `freemkv-flash <dev>` (bare) | no | alias for `info` |
| `freemkv-flash list` | no | list drives by name (`E:`, `/dev/sr1`, `disk4`) and id |
| `freemkv-flash info <dev or file>` | no | INQUIRY, boot banner and family classification, for a drive or a firmware file |
| `freemkv-flash backup <dev> [-o out]` | no | save validated captured firmware (MTK `.bin`, Pioneer `.tar`) |
| `freemkv-flash dump <dev> [-o out.bin]` | RAM logging only, when supported | capture memory and diagnostic responses in one address-oriented file; not flashable |
| `freemkv-flash check <file>` | no | inspect a firmware file without a drive |
| `freemkv-flash package <in.bin> <out.tar>` | no | wrap a standalone BIN or backup in a TAR, offline |
| `freemkv-flash flash <dev> -i <file> [flags]` | with `--execute` | validate and plan; back up before execution, or ask for consent if that is unavailable |
| `freemkv-flash recover <dev> --current <current> -i <target> [flags]` | with `--execute` | experimental recovery without backups |

- Pass a drive by name or id as shown by `list`. It can be omitted when exactly
  one drive is connected.
- `backup` produces one firmware file. For MTK it is a 2 MiB image in the
  vendor's update format: every firmware byte is read from the drive, the boot
  page is stored in its encrypted form, and per-drive settings, calibration and
  revocation lists are replaced with factory contents. It carries no personal
  data and, for most builds, is byte-identical to the OEM update file. Use
  `dump` for a raw copy that keeps the per-drive data. Pioneer candidates with
  zero signatures are usable as Current references, but targets must pass
  transfer authentication.
- `flash` sniffs the input: a `.bin` is a full MTK image; a `.tar` is a MediaTek
  rollback or release package, or a Pioneer envelope package. Pioneer `.enc`
  inputs are also supported. Without `--execute` it is a dry run. `flash` accepts
  TAR packages and standalone BIN images. TARs follow their explicit package
  sequence, and a BIN flashes only the supplied image. No intermediate is inferred
  for a BIN.
- There is no separate `verify` command. `flash` verifies as its protocol allows.

## Usage

```sh
# Identify and classify a drive (default action)
freemkv-flash /dev/sg0
freemkv-flash info /dev/sg0

# Save one restorable firmware backup file
freemkv-flash backup /dev/sg0 -o backup.bin

# Dry-run a flash (prints the plan, issues no writes)
freemkv-flash flash /dev/sg0 -i firmware.tar

# Actually flash (all gates must pass)
freemkv-flash flash /dev/sg0 -i firmware.tar \
    --execute --i-understand-risk

# Reflash the firmware image captured in that backup
freemkv-flash flash /dev/sg0 -i backup.bin --execute --i-understand-risk

# Review a Pioneer OEM transfer against the connected drive; no writes
freemkv-flash flash /dev/sg0 -i update.enc
```

Device argument by OS:

- Linux: `/dev/sgN` (`SG_IO`). May also accept `/dev/srN`.
- Windows: `\\.\CdRomN`.
- macOS: IOKit service or BSD name.

## Automatic diagnostics

The flasher and firmware modifier save detailed diagnostic logs by default on
Windows, macOS and Linux, in both CLI and desktop apps. If an operation fails,
attach its existing log to the bug report. No debug flag or second run is needed.
The CLI prints the path. The desktop apps provide **View diagnostic log…**,
**Copy diagnostic log** and **Save diagnostic log…**, with export beside failures.
See [log contents and locations](crates/freemkv-flash/README.md#diagnostic-logs).

## Backend support

The MediaTek and Pioneer backends have executable flash paths for supported
inputs. MT1959 is the hardware-tested MediaTek path; MT1939 is recognized but
not hardware-validated. Separate Renesas classification does not imply write
support. Unknown families are refused. Pioneer normal Flash checks hardware
family, Kernel tags and bundle consistency. Recovery instead uses the supplied
Current reference to derive receiver credentials.

## Flash workflow

The flasher does not modify the input image. For supported MTK images, it
validates integrity and model compatibility before writing. An image of another
model is admitted only when it is the drive's own hardware family, derived from
the firmware itself (a content hash of chip, platform, loader, interface, medium
and BD-write capability) rather than from a curated list, and only with the full
content-integrity and rollback gates. A different family or an unknown-identity
image is refused, and nothing switches the gate off.

1. **Check the input and receiver.** Validate the selected package and the
   drive's available receiver evidence. Passing a package check does not approve
   drive compatibility; Pioneer's preview explicitly reports that it is pending.
2. **Back up.** Live Flash captures and validates the installed firmware before
   checking compatibility against it. A capture failure requires an explicit
   decision to proceed without a rollback backup; compatibility gates still apply.
3. **Check compatibility and confirm.** Installed-firmware and target checks
   must pass before the desktop confirmation sheet appears. A precheck block
   reports that no firmware was written, with the reason and stopped stage.
4. **Write.** Recheck the tray and live receiver, then perform the prepared
   update. `.bin` streams the full MTK firmware image; `.tar` selects the
   same image from the backup archive and reflashes it.
5. **Verify.** Report startup and supported readback checks separately from
   transfer completion. An execution failure or incomplete verification is not a
   precheck rejection.

### Transport format and Current firmware

The backend chooses the transport format; there is no encryption selector.
MediaTek uses `mediatek-optical` to detect BOOT versus running firmware and
read the active receiver's code signature. It sends plaintext or the encrypted
transport envelope accordingly, and rechecks the identity and signature before
writing.

Flash and Recovery take a Current firmware reference in the same way. The desktop
forms select **Read from drive** by default when the backend supports it.
Otherwise that option is hidden and the firmware currently installed on the drive
is required (not the firmware you want to install). Select its exact member if
the Current TAR is paired. The CLI equivalents are `--current FILE` (with
`--current-member firmware.bin`, or `intermediate.bin` if INTM is running, for a
paired TAR) and `--read-from-drive`. The reference must match the live identity
and build metadata. It supplies receiver code only; backup and readback still use
the drive. Without readable code or a matching Current reference, Flash refuses
before writing.

Pioneer Kernel replacement also requires a signature-derived programming handoff
match: the installed updater's restart address must equal the incoming Kernel's
recognized startup entry. Flash, Recovery and offline crossflash admission refuse
unknown or mismatched handoffs before update entry. Hardware-family equality does
not override this check, and every automatic Kernel restoration pass is checked
too. Offline decisions distinguish `yes`, `soft_no` (a known handoff mismatch
requiring a future intermediate transfer), and `hard_no` (other or unknown
incompatibility). Only `yes` permits writing; catalogue graphs expose soft
refusals as future options.

## Safety

**Do not interrupt a firmware write.** Programming and completion behavior depend
on the backend. No safe abort is guaranteed once writes begin. Eject any disc
first: the tray must be empty and closed.

The gates below only prevent an accidental start. `flash` is a dry run unless
`--execute` is given, and even then refuses to write unless:

- `--i-understand-risk` is given (acknowledging possible bricking),
- a fresh, complete, validated pre-flash backup has been saved, or the operator has
  explicitly agreed to proceed when capture is unavailable,
- the drive classified as a supported family (Unknown is refused).

`--no-backup` (alias `--fast`) skips the pre-flash backup for development. No
rollback file is saved, and gates that need installed-firmware evidence
(crossflash) refuse.

### Recovery

The **Recovery** tab (CLI: `recover`) takes a Current firmware package and a
firmware package to flash. Recovery derives receiver credentials from the
supplied Current firmware, skips automatic backups and installed-versus-target
compatibility policy, and writes the target. It still validates the required
image, receiver and transfer contracts. The dry-run preview comes first. A
precheck rejection writes no firmware; execution failures retain their actual
write and temporary-firmware evidence. The user is responsible for supplying the
correct receiver reference.

```sh
freemkv-flash recover /dev/sg0 --current current.tar -i restore.tar --execute --i-understand-risk
# Explicit alternative to supplying Current (reads firmware, saves no backup):
freemkv-flash recover /dev/sg0 --read-from-drive -i restore.tar --execute --i-understand-risk
```

Success means the drive reports normal mode and readiness (including an empty
tray), not a byte-for-byte readback verification. Recovery sends the target as
supplied, without automatic downgrade patches or extra restoration passes.
Malformed inputs and rejected writes still stop the operation.

**Pioneer.** Both packages must contain Kernel and Normal, and both target
components are written. Current may be an unsigned backup, but the target must
pass transfer authentication; an unsigned candidate is not a signed OEM update.
Recovery enters update mode only when the drive is not already reporting update
mode. While the drive runs Normal firmware, it uses the same target-selected
startup word `0x9F` migration as Flash through A0 before entering update mode;
in update mode it transfers firmware without changing the startup word. No
firmware memory reads or readback occur with a supplied Current file, though
identity and status queries remain necessary. Kernel + Normal updates hand off to
the incoming Kernel before sending Normal, so Flash and Recovery preserve the
paired Normal's OEM encoding and signature. Normal-only preparation uses the
installed Kernel. The shared Normal reencoder requires a complete,
receiver-decoded source image and proves identical contents after conversion; a
bare Normal that cannot be decoded with the available Kernel is refused rather
than guessed. Encoding conversion does not bypass the Kernel handoff,
hardware-family, integrity or authentication gates. Hardware recovery of the
reported PR1ML incident remains unverified.

**MediaTek.** Recovery first identifies the live BOOT or application receiver and
selects plaintext or encrypted transfer from its code. If application code reads
are restricted, supply the exact firmware currently running with `--current`. Its
validated image provides receiver instructions; live INQUIRY, boot banner and
build metadata must match, and are rechecked before entry. This does not prove
every installed byte matches the file. A known family mismatch between a supplied
Current reference and the target is refused before opening the drive.
MediaTek Recovery does not support `--bypass-family-check`. When installed-family
evidence is unavailable, the MediaTek library's recovery admission policy still
applies, and receiver, chip and integrity validation remain required.

Explicit Recovery reports a PREPARE error and continues once with the selected
image. It does not retry PREPARE or ignore firmware-data failures. Normal Flash
still stops on PREPARE failure. This policy does not establish that a failed
PREPARE successfully armed the physical receiver.

MediaTek downloads are TAR packages with an explicit manifest. A paired release
runs its extraction-linked INTM first, confirms startup, then flashes the final
image. When INTM restricts live code reads, Flash analyzes the exact intermediate
it just installed and does not substitute reference bytes into post-write
verification. Protected readback is attempted on the physical drive. If it is
unavailable, paired Flash and Recovery require the target's live application
identity and build metadata and warn that full byte verification was not
completed. Transfer errors, programming faults and byte mismatches remain fatal.
These paths have simulated transport coverage; physical drive validation remains
outstanding.

Recovery accepts the same TAR but writes exactly one selected member, and never
continues to the other member. For a drive already running BH16NS40 INTM,
preview recovery to 1.V9 with:

```sh
freemkv-flash recover DEVICE -i 1.V9.tar --member firmware.bin \
  --current 1.V9.tar --current-member intermediate.bin
```

The Current member is receiver evidence, not another image to flash. A stale
original 1.V1 reference is rejected if INTM is running. Add
`--execute --i-understand-risk` only after reviewing the preview.

## Modify (freemkv-fw)

Modify builds freemkv firmware from an OEM image and signs and verifies its
output automatically; there is no separate Sign action. The CLI is
`freemkv-fw modify INPUT [OUTPUT]` with repeatable `--default FEATURE=VALUE`
options:

```sh
freemkv-fw modify original.bin custom.bin --default hrl=off --default encryption=off
freemkv-fw modify original.bin custom.bin --default region=free --dry-run
```

Supported values are `unrestricted`, `hrl` and `encryption` = `on|off|oem`,
`speed=oem|uncapped`, and `region=oem|free`. HRL Off skips checking; Encryption
Off selects bypass. Omitted settings use shipping defaults. Duplicate assignments,
invalid values, and explicit settings unavailable on the selected firmware are
errors. `--dry-run` validates and reports the build without writing the output;
`--json` includes resolved boot settings and availability. Region selection is
limited to OEM behavior or region-free; specific regions are not exposed.

In the desktop app, **Boot settings** are applied every time the drive starts.
**Reset to defaults** restores unrestricted access to On and the other settings
to OEM behavior; the button changes the form, and Create writes the settings to
the generated firmware. Saved drive settings do not override these boot choices,
though applications can still change settings during a session.

Newly generated images carry a versioned settings record and can be reopened in
Modify to adjust their boot settings. Older modified images without this record
require the original OEM image.

Modify accepts BIN or TAR and returns the same format. With a TAR it modifies only
final firmware, preserves INTM bytes and pairing provenance, and updates the final
member hash. Standalone BIN images and backups can be flashed directly, or
wrapped offline with `freemkv-flash package backup.bin backup.tar`, which never
guesses an INTM pairing.

`--base` requires the complete freemkv base to build successfully; it does not
select a smaller set of modifications. On supported firmware such as BU40N 1.00,
normal creation and `--base` produce identical output for identical boot settings.
Ordinary creation can return partial modifications on other images.

## Implementation layers

`crates/freemkv-flash/src/workflow.rs` provides the CLI and desktop workflows,
and `engine.rs` the family-neutral info, backup and flash gates. Each drive family
is a backend behind the `Backend` trait (`backend/mod.rs`): `backends/mtk/` for
MediaTek MT1959/MT1939 and `backends/pioneer/` for Pioneer. The wire protocols
live in their own crates, [`mediatek-optical`](https://crates.io/crates/mediatek-optical)
and [`pioneer-optical`](https://crates.io/crates/pioneer-optical).
`transport.rs` is the one adapter from the crate's SCSI device
(`platform/adapter.rs`, over `libfreemkv`'s SCSI transport) to both crates, and no
backend source contains a raw CDB opcode (`crates/freemkv-flash/tests/no_cdbs.rs`).
`platform/mock.rs` supports tests without hardware.

## Build and CI

```sh
cargo build --all-targets
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

The workspace `rust-version` is 1.94. CI (`.github/workflows/ci.yml`) runs
formatting and tests at that version, Clippy on stable (`-D warnings`), locked
dependency resolution, and dependency audits. Promotion PRs reuse their branch's
CI; feature PRs and forks run their own checks. Coverage runs on QA and main.

QA (`.github/workflows/qa.yml`) runs release tests with all targets and features
on Linux, macOS, and Windows, plus native GUI gates and every release package's
build and install smoke tests. Release packaging runs on QA, on PRs that touch
packaging, and on release tags, rather than on dev pushes. No firmware release is
published by a branch build.

The test profile optimizes the optical-image and AES-CMAC dependencies to keep
exhaustive catalog authentication fast. Workspace test code retains debug
assertions and overflow checks; release tests use the shipped release profile.
In-memory golden fixtures scope a virtual clock, so settle waits advance the
runtime clock without sleeping. Production and hardware tests keep real waits;
simulation is available only inside library unit tests.

## Pioneer dump format

`freemkv-flash dump` on Pioneer drives writes format v1, which reserves fixed
locations before appending diagnostic responses and a JSON capture directory:

| File range (inclusive) | Source |
|---|---|
| `0x000000–0xBFFFFF` | Low CPU address space; readable B0 memory occupies `0x000000–0x87FFFF` |
| `0xC00000–0xC01FFF` | CPU `0xFFFFE000–0xFFFFFFFF`, selector 92 |
| `0xC02000–0xC022FF` | CPU `0xFF414000–0xFF4142FF`, B0 alias `0x880000` |
| `0xC02300–0xC0FFFF` | Reserved zero fill |
| `0xC10000–0x100FFFF` | Separate selector 93 controller space, offsets `0–0x3FFFFF` |
| `0x1010000` onward | Exact FC log, INQUIRY and other diagnostic responses, then directory/footer |

The FC log is captured first in the order returned by the drive. It is not
silently rotated or substituted for a later RAM snapshot. Unmapped low CPU
addresses remain zero; controller addresses are not assumed to be CPU aliases.
Every read records its CDB, chronological order, destination, returned length,
status and sense. `05/24/00` produces zero-filled unavailable bytes and continues.
Short reads retain their returned bytes; transport failures preserve a partial
capture and stop further drive commands. Unattempted bytes are distinguishable
from observed zeros through the directory's read coverage. Section hashes are
SHA-256 over saved bytes, including any zero fill.

The final 64 bytes contain ASCII `FMVKDMP1`, version and footer size (u32 LE),
directory offset and length (u64 LE), then the directory SHA-256 (32 bytes).
Memory and response bytes retain their original byte order. The JSON directory
records tool version, capture time, device, sections, read coverage and logging
result. Readers find the directory from the footer, so adding responses does not
move the fixed memory regions. Legacy raw dumps remain readable as raw images.

At the end of a dump, `pioneer-optical` inspects the captured executable firmware
for a supported RAM-only CDB logging handler, its dispatch-table binding and its
mask variable. It preserves unrelated mask bits and verifies the live setting.
Missing support or any logging failure is recorded as skipped and never fails
the dump. There is no model or version allowlist, logging flag or checkbox. The
persistent logging API is separate and is never a fallback used by dump.

## License

freemkv's own source is MIT. See [LICENSE](LICENSE).

OEM optical-drive firmware images (test fixtures, build inputs, any firmware
offered for download, and any patched image these tools produce) are the
property of their original manufacturers (LG / Hitachi-LG Data Storage,
MediaTek) and are **not** covered by the MIT license. See [NOTICE](NOTICE).
