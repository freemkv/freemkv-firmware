# freemkv-firmware

Optical-drive **firmware flasher** and **firmware-build pipeline** for freemkv,
written 100% in Rust (a thin `libc` FFI is used only for the Linux `SG_IO`
ioctl; there is no hand-written C and no Python anywhere).

> ⚠️ **Flashing firmware can permanently brick a drive.** This tool issues raw
> SCSI `WRITE_BUFFER` commands. Read the safety section before using `flash`.

## What it is

A CLI (`freemkv-firmware`) that:

- **detects** and classifies the connected optical drive,
- **lists** firmware images from a manifest,
- **flashes** a selected image over SCSI (dry-run by default, guarded by safety
  gates),
- **verifies** and **re-signs** the MediaTek MT1959 AES-CMAC integrity table
  (the "T0" firmware-pipeline proof).

GUI is future work; the CLI (Linux) is the near-term target.

## The drive model: platform A / B and OEM vs freemkv

| Platform | Silicon | Discriminator |
|---|---|---|
| **A** | MediaTek **MT1959** | `MT1959` boot banner @ READ_BUFFER 0x3000 |
| **B** | MediaTek **MT1939** | `MT1939` boot banner |
| — | **Pioneer / Renesas** | RB-0xF1 vendor probe / Pioneer INQUIRY |
| — | **Unknown** | anything ambiguous → **never flashed** |

Detection uses `INQUIRY` (0x12), `GET CONFIGURATION` feature `0x010C`, and
`READ BUFFER` (0x3C mode 6 @ 0x3000). Classification is **fail-safe**: if the
silicon cannot be established it is reported as `Unknown` and refused.

> The exact MT1959-A vs MT1939-B rule is being finalised separately; the
> banner/GET-CONFIG logic is implemented today with a marked `TODO` where the
> final discriminator plugs in (`detect::classify`).

Each firmware image is tagged **OEM-stock** or **freemkv** (patched), plus its
platform (A/B), version, flash mode, and downgrade-enable flag — see
`manifests/example.toml`.

## Integrity model (MT1959 AES-CMAC)

Stock MT1959 images carry a 16-entry AES-CMAC integrity table at file offset
`0x10400` (28-byte entries: `enabled`, `start`, `end`, `cmac[16]`). The key is
**symmetric and public** — it exists to reject accidental corruption and
unsigned third-party images, not to stop a keyholder. The `cmac` module can
`verify` a stock image and `resign` a modified one (data ranges first, the
table-covering range last).

`enc` flashing is a separate, orthogonal layer: an AES-128-ECB **transport
wrapping** of the whole 2 MB image under a host-embedded (non-secret) key,
decrypted by the drive with the same key. It is **not** the vendor OTFAD/signed
layer and does not re-sign CMAC.

## Usage

```sh
# Identify and classify a drive
freemkv-firmware detect --device /dev/sr0

# List firmware in a manifest, grouped by model + kind
freemkv-firmware list --manifest manifests/example.toml

# Verify a stock image's CMAC table (the T0 proof)
freemkv-firmware verify path/to/firmware.bin

# Re-sign a modified image
freemkv-firmware resign in.bin --out out.bin

# Flash (DRY RUN by default — prints the plan, issues no writes)
freemkv-firmware flash \
    --device /dev/sr0 \
    --manifest manifests/example.toml \
    --model BU40N --version N1.02

# Actually flash (all gates must pass)
freemkv-firmware flash --device /dev/sr0 --manifest manifests/example.toml \
    --model BU40N --version 1.05-freemkv --mode full \
    --i-understand-risk --execute
```

## Safety

`flash` is **dry-run unless `--execute`** and additionally refuses to write
unless:

- `--i-understand-risk` is given (acknowledging possible bricking),
- the drive model matches the firmware model — a mismatch requires
  `--allow-cross-flash`,
- the image CRC32 matches the manifest,
- the drive silicon classified as something other than `Unknown`.

## Flash modes

| Mode | Meaning |
|---|---|
| `main` | main code band only |
| `full` | full 2 MB image |
| `enc`  | full image, AES-128-ECB transport-encrypted before send |

All modes stream via `WRITE_BUFFER 0x3B mode 6` in chunks
(`3B 06 <bufid> <off[3]> <len[3]> 00`).

## Platform support

The real SCSI transport is Linux `SG_IO` (`#[cfg(target_os = "linux")]`). Other
platforms build against a **stub** backend so the whole crate compiles and the
offline subcommands (`list`, `verify`, `resign`, dry-run `flash`) work
everywhere; a real Windows SPTI backend and a macOS backend are `TODO`.

## Build / CI

```sh
cargo build
cargo test          # includes the CMAC-verify T0 proof against a stock image
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

CI (GitHub Actions, `.github/workflows/ci.yml`) runs fmt, clippy (`-D
warnings`), build, and test on a **pinned Rust 1.86** toolchain.

## Crate layout

```
freemkv-firmware/
├── Cargo.toml                     # workspace
├── manifests/example.toml
└── crates/freemkv-firmware/
    ├── src/
    │   ├── main.rs                # clap CLI (detect/list/flash/verify/resign)
    │   ├── lib.rs
    │   ├── cmac.rs                # MT1959 AES-CMAC verify + resign
    │   ├── detect.rs              # probes + ChipClass classification
    │   ├── flash.rs               # WRITE_BUFFER upload + enc + safety gate
    │   ├── manifest.rs            # TOML manifest
    │   └── scsi/                  # ScsiDevice trait + linux/stub backends
    └── tests/
        ├── cmac_verify.rs         # T0 proof
        └── fixtures/              # stock base image
```

## License

MIT — see [LICENSE](LICENSE).
