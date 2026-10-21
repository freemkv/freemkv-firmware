# freemkv-flash

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14740/badge)](https://www.bestpractices.dev/projects/14740)

> # ⚠️ BETA — USE AT YOUR OWN RISK
> Hardware validation is limited. A complete MediaTek cycle has been exercised on
> an LG BU40N (rev 1.03). Reported Pioneer failures motivated the experimental
> Recovery workflow; recovery of the affected drive is not yet hardware-verified.
> Flashing can permanently disable a drive. Provided without warranty.

Standalone, multi-OS optical-drive **firmware backup and flasher** for freemkv,
written in Rust with native SCSI transport adapters. This tool issues firmware-write commands — read
the Safety section before using `flash`.

Binary name: `freemkv-flash` (the crate was renamed from `freemkv-firmware`;
the repo directory stays `freemkv-firmware`). Firmware authoring is provided by
the separate `freemkv-fw` binary in this workspace.

## Commands

| Invocation | Writes? | Input | Behavior |
|---|---|---|---|
| `freemkv-flash <dev>` (bare) | no | — | alias for `info` |
| `freemkv-flash list` | no | — | list drives by name (`E:`, `/dev/sr1`, `disk4`) and id |
| `freemkv-flash info <dev>` | no | — | INQUIRY + boot banner + classify family |
| `freemkv-flash backup <dev> [-o out]` | no | — | save validated captured firmware (MTK `.bin`, Pioneer `.tar`) |
| `freemkv-flash dump <dev> [-o out.bin]` | RAM logging only, when supported | — | captures memory and diagnostic responses in one address-oriented file; not flashable |
| `freemkv-flash check <file>` | no | firmware file | inspect without a drive |
| `freemkv-flash recover <dev> --current <current.tar> -i <target.tar>` | with `--execute` | Pioneer Kernel + Normal packages | experimental recovery without backups |
| `freemkv-flash flash <dev> -i <file> [flags]` | with `--execute` | `.tar` or `.bin` | validate and plan; back up before execution or ask for consent if unavailable |

- `backup` produces one firmware file. Pioneer candidates with zero signatures
  are usable as Current references, but targets must pass transfer authentication.
  For MTK
  it is a 2 MiB image in the vendor's update format: every firmware byte is read
  from the drive, the boot page is stored in its encrypted form, and per-drive
  settings, calibration and revocation lists are replaced with factory contents.
  It carries no personal data and, for most builds, is byte-identical to the
  OEM update file. Use `dump` for a raw copy that keeps the per-drive data.
- `flash` sniffs the input: `.bin` = full MTK image; `.tar` = 0.10.x MTK
  rollback archive (rebuilt the same way before flashing), or a Pioneer envelope
  package. Pioneer `.enc` inputs are also supported. Without `--execute`,
  it is a dry run.
- `verify` does not exist as a command. `flash` verifies as its protocol allows.

## Automatic diagnostics

The flasher and firmware modifier save detailed diagnostic logs by default on
Windows, macOS and Linux, in both CLI and desktop apps. If an operation fails,
attach its existing log to the bug report. No debug flag or second run is needed.
The CLI prints the path; desktop apps provide **View diagnostic log…**, **Copy
diagnostic log** and **Save diagnostic log…**, with export beside failures.
See [log contents and locations](crates/freemkv-flash/README.md#diagnostic-logs).

## Backend support

The MediaTek and Pioneer backends have executable flash paths for supported
inputs. MT1959 is the hardware-tested MediaTek path; MT1939 is recognized but
not hardware-validated. Separate Renesas classification does not imply write
support. Unknown families are refused. Pioneer normal Flash checks hardware
family, Kernel tags and bundle consistency. Recovery instead uses the supplied
Current reference to derive receiver credentials; see the limits below.

## Flash workflow

The flasher does not modify the input image. For supported MTK images, it
validates integrity and model compatibility before writing. An image of another
model is admitted only when it is the drive's own hardware family — derived from
the firmware itself (a content hash of chip, platform, loader, interface, medium
and BD-write capability), not from a curated list — and only with the full
content-integrity and rollback gates. A different family or an
unknown-identity image is refused, an unknown family fails closed, and nothing
switches the gate off. Its workflow is:

1. **Check the input and receiver** — validate the selected package and the
   drive's available receiver evidence. Passing a package check does not approve
   drive compatibility; Pioneer's preview explicitly reports that it is pending.
2. **Back up** — live Flash captures and validates the installed firmware before
   checking compatibility against it. A capture failure requires an explicit
   decision to proceed without a rollback backup; compatibility gates still apply.
3. **Check compatibility and confirm** — installed-firmware and target checks
   must pass before the desktop confirmation sheet appears. A precheck block
   reports that no firmware was written, with the reason and stopped stage.
4. **Write** — recheck the tray and live receiver, then perform the prepared
   update. `.bin` streams the full MTK firmware image; `.tar` selects the
   same image from the backup archive and reflashes it.
5. **Verify** — report startup and supported readback checks separately from
   transfer completion. An execution failure or incomplete verification is not a
   precheck rejection.

Recovery prepares the current receiver and selected target before its write,
without Flash's automatic backup or installed-versus-target policy checks. It
still validates the required image, receiver and transfer contracts. Its dry-run
preview precedes desktop confirmation. A precheck rejection writes no firmware;
execution failures retain their actual write and temporary-firmware evidence.

### Transport format

The backend chooses the transport format; there is no encryption selector.
MediaTek uses `mediatek-optical` to detect BOOT versus running firmware and
read the active receiver's code signature. It sends plaintext or the encrypted
transport envelope accordingly, and rechecks the identity and signature before
writing. In the desktop app, a backend that cannot acquire installed firmware
requires a **Current** firmware file in both Flash and Recovery; **Read from drive**
is hidden. MediaTek drives use this file-selection flow. Select the firmware
currently installed on the drive, rather than the firmware you want to install.
The CLI equivalent is `--current FILE`; a paired Current TAR also needs
`--current-member firmware.bin` (or `intermediate.bin` if INTM is running).
The reference must match the live identity and build metadata. It supplies
receiver code only; backup and readback still use the drive. Without readable
code or a matching Current reference, Flash refuses before writing.
Normal flash retains its compatibility checks. The explicit recovery command
uses the separate recovery path described below.

Pioneer Kernel replacement also requires a signature-derived programming handoff
match: the installed updater's restart address must equal the incoming Kernel's
recognized startup entry. Flash, Recovery and offline crossflash admission refuse
unknown or mismatched handoffs before update entry. Hardware-family equality does
not override this check. Every automatic Kernel restoration pass is checked too.
Offline decisions distinguish `yes`, `soft_no` (a known handoff mismatch requiring
a future intermediate transfer), and `hard_no` (other or unknown incompatibility).
Only `yes` permits writing; catalogue graphs expose soft refusals as future options.

## Usage

```sh
# Identify + classify a drive (default action)
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

## Safety

**Do not interrupt a firmware write.** Programming and completion behavior depend
on the backend. No safe abort is guaranteed once writes begin.

The gates below only prevent an accidental *start*; they do nothing once the
write is underway. `flash` is **dry-run unless `--execute`**, and even then
refuses to write unless:

- `--i-understand-risk` is given (acknowledging possible bricking),
- a fresh, complete, validated pre-flash backup has been saved, or the operator has explicitly agreed to proceed when capture is unavailable,
- the drive classified as a supported family (Unknown is refused).

The **Recovery** tab (CLI: `recover`) takes a Current firmware package and a
firmware package to flash. Both Pioneer packages must contain Kernel and Normal.
Recovery derives receiver credentials from the supplied Current firmware, skips
automatic backups and installed-versus-target compatibility policy, and writes
both target components. It enters update mode only when the drive is not already
reporting update mode. No firmware memory reads or readback occur with a supplied
Current file; identity/status queries remain necessary. The user is responsible
for supplying the correct receiver reference.

While the drive runs Normal firmware, Recovery uses the same target-selected
startup word `0x9F` migration as Flash through A0 before entering update mode.
When the drive is already in update mode, that Normal command is unavailable and
Recovery transfers firmware without changing the startup word.

Pioneer Kernel + Normal updates hand off to the incoming Kernel before sending
Normal. Flash and Recovery therefore preserve the paired Normal's OEM encoding
and signature. Normal-only preparation uses the installed Kernel. The shared
Normal reencoder requires a complete, receiver-decoded source image and proves
identical contents after conversion; a bare Normal that cannot be decoded with
the available Kernel is refused rather than guessed. Encoding conversion does
not bypass the Kernel handoff, hardware-family, integrity or authentication gates.

```sh
freemkv-flash recover /dev/sg0 --current current.tar -i restore.tar --execute --i-understand-risk
# Explicit alternative to supplying Current (reads firmware, saves no backup):
freemkv-flash recover /dev/sg0 --read-from-drive -i restore.tar --execute --i-understand-risk
```

Recovery currently supports Pioneer complete packages. Unsupported drives are rejected before firmware reads or update commands. It sends the target as
supplied, without automatic downgrade patches or extra restoration passes.
Malformed inputs and rejected writes still stop the operation. Success means the
drive reports normal mode and readiness (including an empty tray), not a byte-for-byte
readback verification. Hardware recovery of the reported PR1ML incident remains
unverified. Version 0.11.0 removes the public `flash --force` option; use
`recover` for Pioneer recovery. Current may be an unsigned backup, but the target
must pass transfer authentication; an unsigned candidate is not a signed OEM update.

## Implementation layers

`crates/freemkv-flash/src/workflow.rs` provides the CLI and desktop workflows,
and `engine.rs` the family-neutral info, backup and flash gates. Each drive
family is a backend behind the `FirmwareBackend` trait (`drive/mod.rs`):
`drive/mtk/` for MediaTek MT1959/MT1939 and `drive/pioneer/` for Pioneer. The
wire protocols live in their own crates, [`mediatek-optical`](https://crates.io/crates/mediatek-optical)
and [`pioneer-optical`](https://crates.io/crates/pioneer-optical); `drive/transport.rs`
is the one adapter from `libfreemkv`'s SCSI transport (`platform/adapter.rs`)
to both crates, and no backend source contains a raw CDB opcode
(`tests/no_cdbs.rs`). `platform/mock.rs` supports tests without hardware.

## Device argument by OS

- Linux: `/dev/sgN` (`SG_IO`). May also accept `/dev/srN`.
- Windows: `\\.\CdRomN`.
- macOS: IOKit service / BSD name.

## Build / CI

```sh
cargo build --all-targets
cargo test                  # includes the CMAC-verify T0 proof against a stock image
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

CI (`.github/workflows/ci.yml`) runs formatting and tests at the workspace's
`rust-version`, Clippy on stable (`-D warnings`), locked dependency resolution,
and dependency audits. Promotion PRs reuse their branch's CI; feature PRs and
forks run their own checks. Coverage runs on QA and main.

QA (`.github/workflows/qa.yml`) runs release tests with all targets and features
on Linux, macOS, and Windows, plus native GUI gates and every release package's
build/install smoke tests. Release packaging runs on QA, packaging feature PRs,
and release tags, rather than repeating on dev pushes. Linux GUI compilation starts alongside the archive
matrix, then packaging joins the compiled GUI and static CLI artifacts. No
firmware Release is published by a branch build.

The test profile optimizes the optical-image and AES-CMAC dependencies to keep
exhaustive catalog authentication fast. Workspace test code retains debug
assertions and overflow checks; release tests use the shipped release profile.
In-memory golden fixtures explicitly scope a virtual clock: settle waits advance
the runtime clock without sleeping. Production and hardware tests retain real
waits; simulation is available only inside library unit tests.

## License

freemkv's own source is MIT — see [LICENSE](LICENSE).

OEM optical-drive firmware images (test fixtures, build inputs, any firmware
offered for download, and any patched image these tools produce) are the
property of their original manufacturers (LG / Hitachi-LG Data Storage,
MediaTek) and are **not** covered by the MIT license — see [NOTICE](NOTICE).

Pioneer dump format v1 reserves fixed locations before appending diagnostic
responses and a JSON capture directory:

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
the dump. There is no model/version allowlist, logging flag or checkbox. The
persistent logging API is separate and is never a fallback used by dump.

### MediaTek recovery development status

Recovery first identifies the live BOOT/application receiver and selects plaintext or
encrypted transfer from its code. If application code reads are restricted, supply
the exact firmware currently running with `--current`. Its validated image provides
receiver instructions; live INQUIRY, boot banner and build metadata must match, and
are rechecked before entry. This does not prove every installed byte matches the file.
Recovery creates no backup. Model/family comparison against installed firmware is bypassed.

Explicit Recovery reports a PREPARE error and continues once with the selected
image. It does not retry PREPARE or ignore firmware-data failures. Normal Flash
still stops on PREPARE failure. This recovery policy does not establish that a
failed PREPARE successfully armed the physical receiver.

For a drive already running BH16NS40 INTM, preview recovery to 1.V9 with:

```sh
freemkv-flash recover DEVICE -i 1.V9.tar --member firmware.bin \
  --current 1.V9.tar --current-member intermediate.bin
```

The Current member is receiver evidence, not another image to flash. A stale original
1.V1 reference is rejected if INTM is running. Pioneer retains its Current requirement.

MediaTek downloads are TAR packages with an explicit manifest. A paired release
runs its extraction-linked INTM first, confirms startup, then flashes the final image.
When INTM restricts live code reads, Flash analyzes the exact intermediate it just
installed. It does not substitute reference bytes into post-write verification.
Protected readback is attempted on the physical drive. If unavailable, paired Flash
and Recovery require the target's live application identity and build metadata and
explicitly warn that full byte verification was not completed. Transfer errors,
programming faults and byte mismatches remain fatal. These paths have simulated
transport coverage; physical drive validation remains outstanding.

Recovery accepts the same TAR but writes exactly one selected member:
`freemkv-flash recover DEVICE -i release.tar --member intermediate.bin`.
Add `--execute --i-understand-risk` only after reviewing the preview. Recovery
never continues to the other member and does not create a backup.

The Flash and Recovery desktop forms use the same Current firmware and target
layout. Both select **Read from drive** by default when the backend supports it.
Otherwise, that option is hidden and the currently installed firmware file is
required. Select its exact member if the Current TAR is paired.
Recovery uses that selected file even when the drive's receiver code is readable.
The CLI retains its explicit `--current` / `--read-from-drive` options.

Modify's **Boot settings** are applied every time the drive starts. Select
Unrestricted access, HRL checking, Encryption, Read speed, and Region in the
Create form. **Reset to defaults** restores unrestricted access to On and the
other settings to OEM behavior. The button changes the form; Create writes them
to the generated firmware. Saved drive settings do not override these boot
choices; applications can still change settings during a session.

The CLI uses repeatable `--default FEATURE=VALUE` options:

```sh
freemkv-fw create original.bin custom.bin --default hrl=off --default encryption=off
freemkv-fw create original.bin custom.bin --default region=free --dry-run
```

Supported values are `unrestricted`, `hrl`, and `encryption` = `on|off|oem`,
`speed=oem|uncapped`, and `region=oem|free`. HRL Off skips checking; Encryption
Off selects bypass. `enc` aliases `encryption`, and `passthrough` aliases `oem`.
Omitted settings use shipping defaults. Duplicate assignments, invalid values,
and explicit settings unavailable on the selected firmware are errors.
`--dry-run` validates and reports the build without writing the output;
`--json` includes resolved boot settings and availability.

Newly generated images carry a versioned settings record and can be reopened
in Modify to adjust their boot settings. Older modified images without this
record require the original OEM image. Region selection is limited to OEM
behavior or region-free; specific regions are not exposed.

`--base` requires the complete freemkv base to build successfully; it does not
select a smaller set of modifications. On supported firmware such as BU40N
1.00, normal creation and `--base` produce identical output for identical boot
settings. Ordinary creation can return partial modifications on other images.

Modify accepts BIN or TAR and returns the same format. With a TAR it modifies
only final firmware, preserves INTM bytes and pairing provenance, and updates the
final member hash. Standalone BIN images and backups can be flashed directly, or optionally wrapped offline with
`freemkv-flash package backup.bin backup.tar`; this never guesses an INTM pairing.

Flash accepts TAR packages and standalone BIN images. TARs follow their explicit
package sequence; a BIN flashes only the supplied image, with the usual backup,
validation and automatic transfer-encoding checks. No intermediate is inferred
for a BIN. Website downloads remain TAR packages.
