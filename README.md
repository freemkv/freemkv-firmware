# freemkv-flash

> # ⚠️ BETA — USE AT YOUR OWN RISK
> **VERY UNTESTED.** Flashing firmware can **permanently BRICK your drive**.
> Provided with **NO WARRANTY and NO LIABILITY** — if it damages your hardware,
> that is entirely on you. Do **not** run it on a drive you cannot afford to lose.

Standalone, multi-OS optical-drive **firmware flasher / dumper** for freemkv,
written 100% in Rust. This tool issues raw SCSI `WRITE_BUFFER` commands — read
the Safety section before using `flash`.

Binary name: `freemkv-flash` (the crate was renamed from `freemkv-firmware`;
the repo directory stays `freemkv-firmware`). Firmware *authoring* (X→Y
modification: downgrade, speed-lock, AACS host-cert) is deliberately **out of
scope** and will land later as a separate `freemkv-forge` binary.

## Commands — exactly three; `info` is the default

| Invocation | Writes? | Input | Behavior |
|---|---|---|---|
| `freemkv-flash <dev>` (bare) | no | — | alias for `info` |
| `freemkv-flash info <dev>` | no | — | INQUIRY + boot banner + classify family |
| `freemkv-flash dump <dev> [-o out.tar]` | no | — | read per-unit regions → interoperable tar |
| `freemkv-flash flash <dev> -i <file> [flags]` | **yes** | `.bin` or `.tar` | write, then read-back verify |

- `flash` sniffs the input: `.bin` = full 2 MB image; `.tar` = per-unit dump
  (restore regions).
- `verify` does not exist as a command — `flash` **always** read-back-verifies
  after writing. `info`/`dump` never verify.

## MTK-gate (MediaTek-only for now)

Every command classifies the drive first, using only proven discriminators:

| Discriminator | Family | Supported? |
|---|---|---|
| `GET_CONFIG 0x46` feature `0x010C` returns `01 0C` | **MediaTek MT19xx** | ✅ yes |
| `READ_BUFFER 0xF1` succeeds | **Pioneer / Renesas** | classified, ❌ no |
| neither | **Unknown** | ❌ never flashed |

`info` prints the detected family. `dump` and `flash` **abort** on anything but
MediaTek before issuing any dump/flash CDB — running the tool on a Pioneer drive
is safe.

## flash is a dumb verbatim writer

The flasher writes the given file to the drive **verbatim** and never modifies
the image (no DE byte, no downgrade magic, no per-unit splice, no CMAC resign —
those are firmware modification and belong to the future `freemkv-forge`). Its
entire job:

1. **Back up** — always attempt a pre-flash per-unit dump (saved to disk, *not*
   spliced into the image). On dump failure `flash` aborts unless
   `--rescue-no-dump` (the only skip, for a drive that can no longer be read).
2. **Write** — `.bin` streams the whole 2 MB via `WRITE_BUFFER 0x3B mode 6`;
   `.tar` restores exactly the per-unit regions.
3. **Read-back verify** — re-read the written ranges and compare; a mismatch is
   a hard error.

### enc — auto-detected transport envelope

Whether the drive needs the AES-128-ECB `enc` envelope is **auto-detected on
every flash** (`drive::mtk::enc_needed`); the user never decides. Detection is
a known-open question and currently defaults to plaintext. `--enc` / `--no-enc`
exist only as a hidden expert override for debugging.

## Usage

```sh
# Identify + classify a drive (default action)
freemkv-flash /dev/sg0
freemkv-flash info /dev/sg0

# Back up the per-unit regions to a .tar
freemkv-flash dump /dev/sg0 -o backup.tar

# Dry-run a flash (prints the plan, issues no writes)
freemkv-flash flash /dev/sg0 -i firmware.bin

# Actually flash (all gates must pass)
freemkv-flash flash /dev/sg0 -i firmware.bin --mode full \
    --execute --i-understand-risk

# Restore per-unit regions from a dump tar
freemkv-flash flash /dev/sg0 -i backup.tar --execute --i-understand-risk
```

## Safety

**Flashing is a single, irreversible operation.** The drive erases and programs
its flash the moment the 2 MB upload completes (the last streamed chunk) — there
is **no safe abort mid-flight**, and read-back verify only runs *afterward*. Once
`--execute` starts, you are committed. This has had **very little real-hardware
testing** — treat every flash as potentially bricking.

The gates below only prevent an accidental *start*; they do nothing once the
write is underway. `flash` is **dry-run unless `--execute`**, and even then
refuses to write unless:

- `--i-understand-risk` is given (acknowledging possible bricking),
- a pre-flash backup dump succeeded (or `--rescue-no-dump`),
- the drive model matches the firmware model — a mismatch requires
  `--allow-cross-flash`,
- the drive classified as MediaTek (Unknown/Pioneer/Renesas are refused).

## Two independent plug-in layers

```
crates/freemkv-flash/
├── Cargo.toml
└── src/
    ├── main.rs            # clap CLI: info (default) / dump / flash
    ├── lib.rs
    ├── platform/          # OS transport — the ScsiDevice trait
    │   ├── mod.rs         #   trait + open() compile-time OS selection
    │   ├── linux.rs       #   #[cfg(linux)]   real SG_IO ioctl
    │   ├── windows.rs     #   #[cfg(windows)] SPTI stub (unimplemented)
    │   ├── mac.rs         #   #[cfg(macos)]   IOKit stub (unimplemented)
    │   └── mock.rs        #   MockScsiDevice for host-independent tests
    ├── drive/             # chip family — classify + dump/flash
    │   ├── mod.rs         #   Family, classify(), DriveFamily trait
    │   ├── mtk.rs         #   MediaTek MT19xx — fully implemented
    │   ├── pioneer.rs     #   stub: classified, dump/flash Unsupported
    │   └── renesas.rs     #   stub: classified, dump/flash Unsupported
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
warnings`), build, and test on a **pinned Rust 1.86** toolchain.

## License

MIT — see [LICENSE](LICENSE).
