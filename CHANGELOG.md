# Changelog

freemkv-firmware versions independently of the rest of the freemkv stack.
All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.3]

### Changed
- **`Verb::Reset` now has three modes** (mode in `cdb[6]`), fixing an 0.8.2
  misnomer where "reset to OEM" actually restored the baked defaults:
  - `RESET_TO_FLASH` (`0x00`) — reload the saved config (marker-gated); unchanged.
  - `RESET_TO_DEFAULTS` (`0x01`, **new**) — restore the baked create-time
    `DEFAULT_FLAGS` (UHD/BD on) into RAM. This is what boot uses on a never-saved
    drive. (0.8.2's `RESET_TO_OEM` did this — it moved here and got the honest name.)
  - `RESET_TO_OEM` (`0xFF`) — now **true OEM**: forces every RAM flag to
    passthrough AND writes the NV block all-`0xFF` (marker included), leaving the
    drive byte-for-byte identical to a never-saved/never-configured one (**no
    trace**). Because the marker is then `0xFF`, the next boot loads the baked
    defaults, exactly like a fresh drive.

### Notes
- The NV blank is the ordinary SAVE flash primitive with an all-`0xFF` payload
  (op=1 RMW preserves the OEM region record at `+0x4B0`) — no special erase.
- ABI codes are mirrored by `freemkv-unlock` and `freemkv-fw-tester`.

## [0.8.2]

### Fixed
- **UHD/BD media-accept now survives a power-cycle.** The boot hook used to fill
  the feature-flag table with `0xFF` (OEM passthrough) on every power-on, so a
  drive that had UHD enabled only in RAM reverted to *refusing* UHD discs after a
  reboot ("Not Ready — Incompatible medium installed", no current profile), and a
  host that only checks readiness (autorip's drive poll) never saw the disc. The
  boot hook and `RESET`-to-OEM now fill the table from a baked per-create
  **defaults table** instead, and `create` ships **UHD and BD = `STATE_ON`** by
  default — so a flashed drive engages UHD/BD discs out of the box and after every
  power-cycle.

### Added
- **NV saved-marker (flag-table slot 0).** `SAVE` now stamps slot 0 non-`0xFF` to
  record "a config exists"; the boot hook / `RESET`-to-flash apply the saved
  feature bytes only when the marker is set, else fall back to the baked defaults.
  This lets a user deliberately `save` an all-passthrough config (which is
  byte-identical to erased flash) and have it honoured across a reboot, instead of
  being mistaken for "never saved" and overwritten by the defaults.

### Notes
- Defaults are baked into the CMAC-covered boot/reset stubs, so they persist
  through a flash (the NV block itself is not written by the image update).
  Hardware-validated on BU40N: boot→defaults, save→marker→reload honours the saved
  config, reset-to-OEM→defaults. A per-image `--oem-uhd`/`--oem-bd` create opt-out
  (leave a feature at OEM passthrough) is the planned follow-up.

## [0.8.1]

Major firmware redesign (0.7.x → 0.8.x). Pairs with the freemkv stack 1.7.2
(freemkv-unlock mirrors this ABI). Flash with `freemkv-flash flash`, then rip
with autorip / the freemkv CLI 1.7.2.

### Added
- **Vendor ABI v2** — the drive command grammar is now verb + feature + state:
  `Save` (0x0B), `RESET`-to-flash/OEM modes, and explicit encodings for the seven
  orthogonal feature flags (Speed, Region, UHD, BD, HRL, AKE, BUS). The
  HRL/AKE/BUS unlock direction is `off = unlock` (`0x00`). Vendor-command data-in
  is floored at `MIN_ALLOC_LEN` (the drive aborts a sub-16-byte data-in — HW-confirmed).
- **Seven orthogonal feature flags** exposed and reported by `base` availability.
  "Raw read" is host-composed (AKE-off + BUS-off), not a firmware feature.
- **MT1939-classic support** — classic base create/verify (118/118) with
  classic-specific feature gates; boot-init hook blessed on emulation evidence.
- **SAVE/RESET/boot foundation** — persist the feature table to flash and reload
  it on boot; signature-derived NV SAVE-home.

### Changed
- UHD folded into the single REPORT-KEY media-accept gate (one media check, not two).
- All AACS finders de-hardcoded to full-image signature match with a uniqueness
  guard (no hard address windows / pinned frame slots), fixing cross-variant misses.
- Engine split into a shared core + per-lineage builders; golden KAT regenerated.

### Feature availability (118-image OEM corpus)
- Region / AKE / BUS / HRL: 118/118. Speed / UHD / BD: 101/118 (the 17
  MT1939-classic images lack these by genuine architectural limitation).

## [0.7.1]

### Added
- `freemkv-flash info` now identifies **every** drive family in a firmware image,
  not just MediaTek MT19xx: Pioneer (raw + zlib-packaged), legacy Hitachi-LG
  (HL-DT-ST) full-flash dumps, Renesas and MediaTek-bridge dumps, the encrypted
  MediaTek envelope, and ASCII Intel-HEX images — each reported with honest
  flashability (only MT19xx is flashable) and integrity where applicable.

### Changed
- `freemkv-flash flash` now writes only with a **closed, empty tray** — it refuses
  a loaded disc or an open tray (each with a distinct message) before any write.

### Validated
- **Hardware-proven on the LG BU40N (MT1959).** `freemkv-fw create` output flashed
  cleanly (read-back + on-device CMAC verified), `freemkv-hwtest` passed all lever
  checks, the AACS bus-decrypt KAT read byte-identical to the golden MK/LibreDrive
  reference, and a full UHD autorip produced an ISO **byte-identical to MakeMKV**.

## [0.7.0]

### Security
- `freemkv-flash`: the flash write path now refuses — unconditionally, with no
  override — to write an image whose AES-CMAC does not verify, or whose
  drive-descriptor model (file offset 0x1EC000) does not name the target drive's
  INQUIRY product. Either gap could brick a good drive: a mis-signed/corrupted
  image the drive's boot authenticator rejects, or a right-family/wrong-model
  image (every MT19xx image CMAC-verifies for its OWN model, so CMAC alone can't
  catch that). Both gates run before any SCSI write; a dry-run stays a pure
  read-only inspection.

### Fixed
- `freemkv-fw`: two out-of-bounds panics on a malformed or short OEM image — the
  `ldr [pc,#imm]` literal-pool read past the image tail, and the Gate-A
  deny-reset site index — now fail closed (`None` / a clear error) instead of
  panicking. Added coverage for the flasher's failed-backup abort gate and for
  `freemkv-hwtest`'s hung-helper timeout/kill.

### Added
- `freemkv-hwtest`: a data-driven, single-framing hardware-test harness (YAML
  scripts, one `call_cdb` seam) that replaces the old `scripts/fw_hwtest.sh`
  shell suite. Every knock/read goes through libfreemkv's real SCSI transport so
  the data-phase framing can't drift between steps. Covers the full command
  matrix disc-less and disc, per-mode reliability soaks, and the cert-AKE matrix.

### Changed
- `freemkv-fw`: finalised the command set — `01` Identity, `02` Speed, `03`
  Region, `04` Raw Read, `09` DumpAll. Raw Read `0x04` has three states: `00`
  OEM enforce, `01` "cert valid" (a bare `READ DISC STRUCTURE` `0xAD` returns the
  Volume ID with no AKE), `02` "accept any host cert" (forces the AKE to state 6
  so the host can run a real AKE with a revoked cert). Speed/Region/Raw Read are
  flag-gated OEM-code trampolines; the `3C 0E` handler persists `flag[subfn]`.

### Fixed
- `freemkv-fw`: the Raw Read `01` producer (Gate-A) trampoline now resets the
  per-AGID session selector before the VID producer runs, so a prior read or a
  `04 00` deny can't leave the selector `>= 2` and make the producer abort
  (`ABORTED COMMAND`) until a power-cycle. The deny path also idles the AACS
  engine via the OEM `aacs_session_reset` so a denied read never wedges the next.

## [0.6.2]

### Changed
- `freemkv-fw`: Raw Read (subfn `0x04`) is now a **flag-gated AKE accept-gate
  trampoline**, not a `set_agid_state` poke. Grounded from the MK GOLD dump: MK
  runs the drive's own AKE (request-code `6`) rather than faking the gate byte, and
  the per-AGID state is a `1→…→6` machine whose terminal `6` is only reached by the
  real key-exchange. `find_ake_gate()` locates (by a signature byte-identical across
  OEM 1.00 and MK 1.03) the success/reset state writers; the detour rewrites the
  RESET writer so a failed host-cert verify is forced to state `6` (accept) when
  `flag[0x04]` is set, else the OEM `1`. The host drives the AKE (`0xA3`/`0xA4`) and
  reads the VID via `0xAD`; the firmware only defeats the cert-signature rejection.
- Removed the 0.6.1 `set_agid_state` approach (proven insufficient: forcing state
  `6` skips the AKE steps that populate the session buffers the VID producer needs).

## [0.6.1]

### Changed
- `freemkv-fw`: subfn `0x03` is now **Raw Read** — a host-cert approve
  (`set_agid_state(0/1, 6)`, returns GOOD). The host then reads the VID via
  `READ DISC STRUCTURE` (`0xAD` fmt `0x80`) and sectors via `READ(10)`; bus enc is
  off for free (no AKE ⟹ no bus key), so `0x04` is dropped.

### Fixed
- `freemkv-fw`: the prior `0x03` called the OEM VID producer/dispatcher inline,
  which hard-wedged the controller on a BU40N (Hardware Error → dead SATA target,
  host reboot to recover). Raw Read never calls them — failure is now a harmless
  CHECK CONDITION.

## [0.6.0]

### Added
- `freemkv-fw`: the freemkv drive command works on real hardware. `create`
  builds firmware that answers a vendor `READ BUFFER` knock — sub-function `01`
  returns `freemkv <version>`; `02`–`06` are reserved placeholders that prove
  the command dispatch before each feature's real code lands. Any non-freemkv
  command passes straight through to the stock handler. Confirmed on an LG BU40N.
- Code-grounded, per-chip engine: every address the build touches is derived
  from the drive's own firmware, never hardcoded, with a known-answer test that
  reproduces the proven image exactly.

### Changed
- `freemkv-flash` now shares libfreemkv's SCSI transport instead of a local copy.
- Toolchain moved to Rust 1.94.

## [0.5.0]

### Added
- `freemkv-flash`: standalone, multi-OS optical-drive firmware flasher/dumper,
  100% Rust. Three commands — `info` (default, identify + classify), `dump`
  (per-unit backup to an interoperable tar), `flash` (verbatim writer; dry-run
  planner by default, gated behind `--execute --i-understand-risk`).
- Layered architecture: CLI → generic `engine` (chip-agnostic orchestration:
  file read, pre-flash backup, dry-run plan, streaming loop, read-back verify,
  safety gate) → per-chip `DriveFamily` trait. MediaTek MT19xx is fully
  implemented; Pioneer/Renesas classify positive but are unsupported (the
  MTK-gate keeps them safe — no dump/flash CDB is ever issued).
- AES-128-ECB `enc` transport envelope (auto-detected, default plaintext).
- MT1959 AES-CMAC verify/resign; TOML firmware-image manifest.
- Standard OSS files (LICENSE, CODE_OF_CONDUCT, CONTRIBUTING, SECURITY) and a
  `dev → qa → main` CI model (CI on pinned Rust 1.86, a QA gate, and a
  self-contained leak-guard) matching the rest of the freemkv ecosystem.

### Robustness
- Linux SG_IO transport hardened for adversarial/degraded drives: a CHECK
  CONDITION on a data-IN read is never accepted as valid data (a failed region
  read can no longer silently corrupt a backup); a self-clearing UNIT ATTENTION
  is retried once on reads/polls (so a benign power-on notification does not
  masquerade as a failure), and NOT READY now gates the flash-open handshake
  before any WRITE BUFFER is issued. The post-burn COMMIT/READY/SENSE trailers
  are best-effort: only a real programming fault (sense key 0x3/0x4/0xB) reports
  the irreversible flash as failed.

### Notes
- `flash` is a **dumb verbatim writer**: it never modifies the image. Firmware
  authoring (downgrade, speed-lock, host-cert changes) is deliberately out of
  scope for a separate future tool.
