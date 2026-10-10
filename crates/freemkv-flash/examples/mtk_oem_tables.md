# MediaTek OEM backup catalog

`src/drive/mtk/oem.bin` lets a MediaTek backup rebuild the vendor's update image
from a drive read. Regenerate it from a directory of OEM MT1959/MT1939 update
images:

```sh
cargo run --release -p freemkv-flash --example mtk_oem_tables -- \
  /path/to/hoard/images/mediatek \
  crates/freemkv-flash/src/drive/mtk/oem.bin
```

Drive reads and images whose chip cannot be named are skipped. A content key
shared by builds with different factory contents is left out, so those builds
fall back to their chip's defaults. Every admitted build must rebuild
byte-for-byte from a simulated drive read, or the run fails.

Then run the flash tests and the corpus regression:

```sh
FREEMKV_MTK_IMAGES=/path/to/hoard/images/mediatek \
  cargo test -p freemkv-flash corpus_rebuilds_byte_exact -- --ignored
```

The executable embeds the catalog at compile time.
