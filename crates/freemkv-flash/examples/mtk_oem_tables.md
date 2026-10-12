# MediaTek OEM backup catalog

`src/backends/mtk/oem.bin` lets a MediaTek backup rebuild the vendor's update image
from a drive read. Regenerate it from a directory of OEM MT1959/MT1939 update
images:

```sh
cargo run --release -p freemkv-flash --example mtk_oem_tables -- \
  /path/to/hoard/images/mediatek \
  crates/freemkv-flash/src/backends/mtk/oem.bin \
  /path/to/hoard/index/sources.json
```

Drive reads and images whose chip cannot be named are skipped. Only OEM
builds are admitted; the run prints every other image with its reason:

- its AES-CMAC integrity table fails;
- it carries freemkv-fw's identity magic (a freemkv-fw build);
- it was not decoded from inside a vendor updater executable (a loose image
  has no origin to check, and the CMAC key is public, so a re-signed build
  verifies);
- the hoard marks it patched (`mediatek.patched` in its `.json` sidecar);
- a source it was found under names a modified or community build (`DE_`,
  `Downgrade Enabled`, `unMK`, `MK Firmware`, `MK_edited`, `OmniDrive`, dumps),
  from the sidecar and, when given, the hoard's `sources.json`;
- its calibration block holds more than the factory `VENDOR_INFO` header (a
  drive dump with one unit's calibration);
- it has no hardware family;
- it equals another admitted build except for a `0xDE` downgrade-enable byte
  (a DE-patched copy).

A content key shared by builds with different factory contents is left out,
so those builds fall back to their chip's defaults. Every admitted build must
rebuild byte-for-byte from a simulated drive read and keep its hardware family
under it, or the run fails. Each build records its chip, family and hardware
key (`family_scheme` `mediatek.hardware.v1`).

Then run the flash tests and the corpus regression:

```sh
FREEMKV_MTK_IMAGES=/path/to/hoard/images/mediatek \
  cargo test -p freemkv-flash corpus_backups_are_exact_only_for_oem_builds -- --ignored
```

The executable embeds the catalog at compile time.
