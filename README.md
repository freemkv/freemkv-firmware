# freemkv-flash

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14740/badge)](https://www.bestpractices.dev/projects/14740)

> # ⚠️ BETA — USE AT YOUR OWN RISK
> **Barely tested.** A full flash cycle (backup → flash → verify) has been
> exercised on **exactly one drive model — an LG `HL-DT-ST BD-RE BU40N` (rev
> 1.03, MediaTek MT19xx)** — and **nothing else**. Every other drive, model, and
> firmware is **completely untested**. Flashing firmware can **permanently BRICK
> your drive**. Provided with **NO WARRANTY and NO LIABILITY** — if it damages
> your hardware, that is entirely on you. Do **not** run it on a drive you cannot
> afford to lose.

Standalone, multi-OS optical-drive **firmware backup and flasher** for freemkv,
written 100% in Rust. This tool issues raw SCSI `WRITE_BUFFER` commands — read
the Safety section before using `flash`.

Binary name: `freemkv-flash` (the crate was renamed from `freemkv-firmware`;
the repo directory stays `freemkv-firmware`). Firmware *authoring* (X→Y
modification: downgrade, speed-lock, AACS host-cert) is deliberately **out of
scope** and will land later as a separate `freemkv-fw` binary.

## Commands

| Invocation | Writes? | Input | Behavior |
|---|---|---|---|
| `freemkv-flash <dev>` (bare) | no | — | alias for `info` |
| `freemkv-flash list` | no | — | list drives by name (`E:`, `/dev/sr1`, `disk4`) and id |
| `freemkv-flash info <dev>` | no | — | INQUIRY + boot banner + classify family |
| `freemkv-flash backup <dev> [-o out]` | no | — | save one validated, flashable backup (MTK `.bin`, Pioneer `.tar`) |
| `freemkv-flash dump <dev> [-o out.bin] [--force]` | no | — | raw 0x0..0x600000 device read (Pioneer; diagnostics, not flashable) |
| `freemkv-flash flash <dev> -i <file> [flags]` | with `--execute` | `.bin` or `.tar` | validate and plan; execute only after fresh backup |

- `backup` produces one file that can be passed directly to `flash -i`. For MTK
  it is a 2 MiB image in the vendor's update format: every firmware byte is read
  from the drive, the boot page is stored in its encrypted form, and per-drive
  settings, calibration and revocation lists are replaced with factory contents.
  It carries no personal data and, for most builds, is byte-identical to the
  OEM update file. Use `dump` for a raw copy that keeps the per-drive data.
- `flash` sniffs the input: `.bin` = full MTK image; `.tar` = 0.10.x MTK
  rollback archive (rebuilt the same way before flashing). Without `--execute`,
  it is a dry run.
- `verify` does not exist as a command. `flash` verifies as its protocol allows.

## Automatic diagnostics

The flasher and firmware modifier save detailed diagnostic logs by default on
Windows, macOS and Linux, in both CLI and desktop apps. If an operation fails,
attach its existing log to the bug report. No debug flag or second run is needed.
The CLI prints the path; desktop apps provide **View diagnostic log…**, **Copy
diagnostic log** and **Save diagnostic log…**, with export beside failures.
See [log contents and locations](crates/freemkv-flash/README.md#diagnostic-logs).

## MTK-gate (MediaTek-only for now)

Every command classifies the drive first, using only proven discriminators:

| Discriminator | Family | Supported? |
|---|---|---|
| `GET_CONFIG 0x46` feature `0x010C` returns `01 0C` | **MediaTek MT19xx** | ✅ yes |
| `READ_BUFFER 0xF1` succeeds | **Pioneer / Renesas** | classified, ❌ no |
| neither | **Unknown** | ❌ never flashed |

`info` prints the detected family. For Pioneer, **use `backup`, not `dump`**:
`backup` captures a flashable OEM-format package (two `.enc` components in a
tar); `dump` is a raw, non-flashable device snapshot for diagnostics. Pioneer
`flash` is gated by a hardware-family check, a Kernel-tag check, and bundle
self-consistency; see [`crates/freemkv-flash/README.md`](crates/freemkv-flash/README.md) for
the full command reference and policy.

## Flash workflow

The flasher does not modify the input image. For supported MTK images, it
validates integrity and model compatibility before writing. Its workflow is:

1. **Back up** — a live execution reads and saves a fresh, complete, validated
   rollback archive. A failed backup stops the flash before any firmware write.
2. **Write** — `.bin` streams the full MTK firmware image; `.tar` selects the
   same image from the backup archive and reflashes it.
3. **Verify** — the backend performs its supported completion/read-back checks.

### Transport format

The backend chooses the transport format; there is no encryption selector.
The implemented MTK route sends a validated plaintext image. This is a protocol
choice, not a universal encryption-detection probe for every MediaTek drive.

## Usage

```sh
# Identify + classify a drive (default action)
freemkv-flash /dev/sg0
freemkv-flash info /dev/sg0

# Save one restorable firmware backup file
freemkv-flash backup /dev/sg0 -o backup.bin

# Dry-run a flash (prints the plan, issues no writes)
freemkv-flash flash /dev/sg0 -i firmware.bin

# Actually flash (all gates must pass)
freemkv-flash flash /dev/sg0 -i firmware.bin \
    --execute --i-understand-risk

# Reflash the firmware image captured in that backup
freemkv-flash flash /dev/sg0 -i backup.bin --execute --i-understand-risk

# Review a Pioneer OEM transfer against the connected drive; no writes
freemkv-flash flash /dev/sg0 -i update.enc
```

## Safety

**Flashing is a single, irreversible operation.** The drive erases and programs
its flash the moment the 2 MB upload completes (the last streamed chunk) — there
is **no safe abort mid-flight**, and read-back verify only runs *afterward*. Once
`--execute` starts, you are committed. A full cycle has been exercised on **one
drive model only (an LG BU40N, rev 1.03)** — every other drive is untested;
treat every flash as potentially bricking.

The gates below only prevent an accidental *start*; they do nothing once the
write is underway. `flash` is **dry-run unless `--execute`**, and even then
refuses to write unless:

- `--i-understand-risk` is given (acknowledging possible bricking),
- a fresh, complete, validated pre-flash backup has been saved,
- the drive classified as a supported family (Unknown is refused).

`flash --force` consolidates crossflash and degraded-drive recovery. It attempts
a backup but permits proceeding if backup capture/validation fails. Input
structure, integrity, and supported write-protocol requirements still apply.

## Two independent plug-in layers

```
crates/freemkv-flash/
├── Cargo.toml
└── src/
    ├── main.rs            # clap CLI: list / info / check / backup / dump / flash
    ├── lib.rs
    ├── platform/          # OS transport — the ScsiDevice trait
    │   ├── mod.rs         #   trait + open() compile-time OS selection
    │   ├── linux.rs       #   #[cfg(linux)]   real SG_IO ioctl
    │   ├── windows.rs     #   #[cfg(windows)] SPTI stub (unimplemented)
    │   ├── mac.rs         #   #[cfg(macos)]   IOKit stub (unimplemented)
    │   └── mock.rs        #   MockScsiDevice for host-independent tests
    ├── drive/             # chipset/protocol backends — probe + backup/flash
    │   ├── mod.rs         #   Family, classify(), DriveFamily trait
    │   ├── mtk.rs         #   MediaTek MT19xx — fully implemented
    │   ├── pioneer.rs     #   Pioneer OEM backup/flash (dry-run unless --execute)
    │   └── renesas.rs     #   classified; live backup/flash blocked
    ├── cmac.rs            # MT1959 AES-CMAC verify + resign
    └── manifest.rs        # TOML firmware-image manifest / flash mode
```

## Device argument by OS

- Linux: `/dev/sgN` (`SG_IO`). May also accept `/dev/srN`.
- Windows: `\\.\CdRomN` (SPTI backend is a stub for now).
- macOS: IOKit service / BSD name (IOKit backend is a stub for now).

## Build / CI

```sh
cargo build --all-targets
cargo test                  # includes the CMAC-verify T0 proof against a stock image
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

CI (GitHub Actions, `.github/workflows/ci.yml`) runs fmt, clippy (`-D
warnings`), build, and test on the **stable** Rust toolchain.

## License

freemkv's own source is MIT — see [LICENSE](LICENSE).

OEM optical-drive firmware images (test fixtures, build inputs, any firmware
offered for download, and any patched image these tools produce) are the
property of their original manufacturers (LG / Hitachi-LG Data Storage,
MediaTek) and are **not** covered by the MIT license — see [NOTICE](NOTICE).
