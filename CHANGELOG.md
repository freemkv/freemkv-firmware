# Changelog

freemkv-firmware versions independently of the rest of the freemkv stack.
All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.8]

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
