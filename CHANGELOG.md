# Changelog

freemkv-firmware versions independently of the rest of the freemkv stack.
All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
