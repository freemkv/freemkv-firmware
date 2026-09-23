# Changelog

freemkv-firmware versions independently of the rest of the freemkv stack.
All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.14]

### Changed
- **Every Thumb primitive now comes from the standalone `thumb-asm` crate.**
  `crates/freemkv-fw/src/thumb.rs` collapsed to a thin shim over
  `thumb_asm::*` plus two anyhow-flavored install-guard helpers
  (`assert_bl_install` / `assert_b_wide_install`). Byte-for-byte identical
  emit verified (image sha256 pre- and post-migration match). Path-dep
  during co-development; the crate is at `../../thumb-asm` awaiting a
  crates.io publish.

### Added
- **Emit-time install guards at every detour site.** After each
  `thumb::write(&mut buf, site, &bl)` in `mt1959.rs` and
  `mt1939_classic.rs` the 4 bytes are decoded back and asserted to reach
  the intended stub VA. Twelve sites total — Speed, Region, Gate-A,
  deny-reset, UHD, HRL (per loop iteration), BD, plus the classic Region,
  Gate-A, AKE, HRL (per loop iteration), and the shared classic
  `commit_classic_detour` covering UHD+BD. Would have caught the 0.8.13
  BL-over-tail-call bug at emit time.
- **`AkeInstallShape` regression KAT.** The byte-exact hand-built KAT now
  additionally decodes the AKE detour site on the fixture image and
  asserts (a) it decodes as a wide `B.W` to `ake_stub_va`, (b) it does
  NOT decode as a `BL`. Prevents any future silent reversion of the
  install shape.

### Fixed
- **BU40N/desktop AKE detour install is now a wide `B`, not a wide `BL`.** The
  AKE reject-writer site (`AKE_GATE_SIG`'s `match+12`) has an OEM tail-call
  idiom: `movs r1,#1; b <set_agid_state>`. `set_agid_state` is a shared leaf
  that returns via `bx lr`, using the OUTER function's `lr` (set by *its*
  caller). Installing a `bl <build_ake_stub>` here clobbered `lr` with
  `site+4`, so `set_agid_state`'s `bx lr` no longer returned to the outer
  caller — it fell into an unrelated leaf at `site+4` that clears bit 0x10
  of MMIO `0x04000000`, disabling drive-side bus-encryption at boot on every
  reject-arm path (fires on the drive's internal AKE cycle at disc-load,
  before any host command). Symptom: fresh cold-boot with `Encryption=0xFF`
  should have left the drive bus-wrapped like OEM, but empirically it
  came up de-bussed. The install is now a Thumb-2 wide `B` (`B.W`, T4 —
  same 4 bytes, `hw2` base `0x9000` instead of `0xD000`) so `lr` flows
  unchanged through the detour and the tail-call semantics match OEM
  exactly. `ake_detour` now returns an `AkeInstallShape` enum so the caller
  picks `B.W` for the BU40N/desktop tail-call site and `BL` for the NB-class
  shared-`bl` sites (which were correct as-is because OEM already had a
  `bl` there). Added `thumb::encode_b_wide` and `thumb::decode_b_wide` next
  to their `bl` counterparts. Audit updated to accept either encoding at
  the AKE install site.

## [0.8.13]

### Fixed
- **`Feature::Encryption` revert now actually re-arms the drive-side bus.** The
  0.8.12 revert used the plain `aacs_session_reset` primitive at VA `0xCAE18`,
  which empirically tears the AGID ladder down but does NOT re-arm bus-encryption
  (kickoff Fact 4: direct call returns SCSI Good, drive alive, but the state
  cell at `0x01ff9e04` and every observable read is identical before/after).
  The correct primitive is the OEM's own **session-rearm wrapper** at
  `0x00044874` on BU40N 1.00 — the routine OEM firmware itself calls at
  disc-insert / medium-loaded to bring the AACS session UP. That wrapper does
  `aacs_session_reset` PLUS the six subsystem re-inits it tears down, including
  the bit-20 write to the engine control word (`ldr r0,[r2,#4]; movs r1,#1;
  lsls r1,#0x14; orrs r0,r1; str r0,[r2,#4]` — the "arm bus-encryption" store
  the plain reset lacks) and the AACS coprocessor arm mailbox
  (`r0=1; blx 0xd9b68`). The SET-Encryption arm now bakes this wrapper as the
  revert target with a rearm-first / reset-fallback resolution, so `SET
  encryption 0xFF` (or `0x01`) from a de-bussed session re-wraps the drive
  synchronously and the fw obeys the flag in both directions — the runtime
  half of the "6 flags in NV; boot loads; fw obeys; SET re-obeys" contract.
- **Uniqueness-verified finder for the rearm wrapper.** `find_aacs_session_rearm`
  matches a 32-byte inner idiom (three wildcard BLs + the six-halfword bit-20
  bus-enc arm store + a wildcard BL + the first halfword of the BL to
  `aacs_session_reset`); the trailing BL's target is decoded and required to
  equal the already-resolved `find_aacs_session_reset` entry, so the match is
  proven-unique image-wide and cannot ship a mis-patched revert.

## [0.8.12]

### Fixed
- **`Feature::Encryption` is now truly bidirectional.** `SET encryption` to a
  non-off state (`0xFF` passthrough / `0x01` on) now invokes the OEM
  `aacs_session_reset` primitive so any latched de-bus session is torn down
  synchronously — the flag can be flipped back to OEM and the *drive actually
  reverts to bus-wrapped reads*. Previously the drive could stay latched
  de-bussed after the initial `set encryption 0x00`, so `set encryption 0xFF`
  only *read* right but didn't *do* what it said. `SET encryption 0x00` is
  unchanged (the AKE detour applies the de-bus on the next read); the reset is
  emitted only on the revert direction. `aacs_reset` resolution is best-effort
  (`.unwrap_or(0)`), so images whose signature doesn't match still build — the
  handler simply skips the emit block on those.

## [0.8.11]

### ABI BREAK
- **Removed `Feature::Bus`** (wire id `0x07` retired). Empirically proved on
  BU40N/MT1959 that toggling `Bus` alone had no observable content-decrypt effect
  — the drive-side bus wrap was inert as a *separate* datapath lever. The Bus
  toggle is gone from the wire ABI; `0x07` is unassigned.
- **Renamed `Feature::Ake` (`0x06`) → `Feature::Encryption`.** The single
  consolidated master encryption/cert bypass: `STATE_OFF` (`0x00`) = every
  drive-side encryption/cert requirement gone (cert-AKE relaxed, bus-wrap off —
  what used to need a cert now doesn't); `STATE_PASSTHROUGH` (`0xFF`) = OEM
  real handshake; `STATE_ON` (`0x01`) = require the real handshake. Hosts that
  used to write `Ake=off + Bus=off` now write **one** `Encryption=off`.
- **Added `Verb::Reboot` (`0x0F`)** — DEBUG_KNOCK-only. Invokes the firmware's
  boot function entry with `r0=4` to force the cold path (BSS clear + C-runtime
  data init + full post-init). Recovers a wedged drive without a power cycle;
  the safe-knock verb chain is re-armed to its power-on defaults. The target VA
  is baked into the emitted handler at build time (`boot_init_site - 0x10`), so
  no CDB arguments are carried beyond the verb byte.
- **Added `Verb::Call` (`0x0C`)** — DEBUG_KNOCK-only. Interactive `blx target`
  primitive: `CDB[5..9]` = 32-bit target VA (BE); `CDB[9]` = single u8 loaded
  into `r0`. Non-durable / diagnostic.
- **Added `Verb::Poke` (`0x0D`)** — DEBUG_KNOCK-only. Poke a single byte to an
  arbitrary address: `CDB[5..9]` = 32-bit target (BE); `CDB[9]` = value. NO
  bounds check. Non-durable / diagnostic.
- **Added `DEBUG_KNOCK` (`DE B9`)** — a distinct two-byte knock at `cdb[2..4]`,
  by-construction different from the safe [`KNOCK`] (`C0 DE`). Debug-only verbs
  (`Call`, `Poke`, `Reboot`) dispatch ONLY under `DEBUG_KNOCK`; safe verbs
  dispatch ONLY under `KNOCK`. The two dispatches never cross, so a typo of a
  safe verb vs a debug verb under the wrong knock always falls through to a
  zeroed reply — `Call`/`Poke`/`Reboot` can never be accidentally invoked via
  the safe knock, and no safe verb can be accidentally invoked via `DEBUG_KNOCK`.

### Fixed
- **DEBUG_KNOCK fall-through into safe dispatch** — the `debug_ok` block's
  unknown-verb arm now clobbers `r4` before falling through to `clr`, so a
  safe-verb id in `cdb[4]` under `DEBUG_KNOCK` can never execute the safe verb.
- **Classic `Verb::Reboot` baked the wrong VA** — the classic build path now
  reports `boot_function_entry == 0` and emits an INERT Reboot arm (no `blx`),
  because `site - 0x10` on classic does not point at a valid function entry.
  The verb still returns a zeroed reply; it just doesn't reset.
- **Feature id `0` in SET/GET** — the handler's bounds check now rejects id `0`
  in both the SET and GET arms. Slot 0 is the NV saved-marker cell; a SET with
  id `0` would have overwritten the marker (making a genuinely-saved config
  look never-saved), and a GET with id `0` would have leaked it.

### Removed
- **Dead detours:** `debus_detour`, `busenc_detour`, and the SET-time bare-VID
  replay are gone. Consolidation into a single `Encryption` feature made all
  three redundant: the one gate that empirically moves the needle stays, the
  others are dead code paths that added exploit surface without effect.

## [0.8.4] – [0.8.10] (unreleased umbrella)

The 0.8.4–0.8.10 window collapsed the wire ABI to its post-hardware-proof
shape. No 0.8.4–0.8.10 image ever shipped as a tagged release; the individual
version bumps served as milestones in the KAT-locked emit-byte progression. The
consolidated highlights:

### Added
- **Debug-knock family (built up across 0.8.7–0.8.9):** `Verb::Call`,
  `Verb::Poke`, and `Verb::Reboot` all landed under a distinct `DEBUG_KNOCK`
  (`DE B9`) at `cdb[2..4]`. The fw's dispatch NEVER crosses knocks: safe verbs
  under safe knock only, debug verbs under debug knock only. Positional KAT
  assertions lock the emitted Reboot arm to its `bne / ldr r6,[pc,#imm] / movs
  r0,#4 / blx r6` shape.
- **Structural release-gate audit checks `Verb::Reboot`** — when the build path
  resolves a `boot_function_entry` (modern MT1959 geometry), the emitter now
  records the entry as an `Identity` lever fact and the audit verifies the
  Thumb-tagged 32-bit literal `entry | 1` is present in the injected handler.
  Classic builds report `entry == 0` and the check is skipped.

### Changed
- **Consolidation of Ake + Bus → Encryption (0.8.10).** Empirical bench work on
  BU40N/MT1959 proved `Bus` inert as a *separate* lever; the AKE-bypass path
  alone de-busses content on the wire. The two independent features are now
  one master `Encryption` feature at wire id `0x06`; wire id `0x07` is retired.
- Number of orthogonal feature flags: **7 → 6**.
- Feature-flag table SRAM span: `NUM_FEATURES + 1 = 7 bytes` (slot 0 = NV
  saved-marker; slots `0x01..=0x06` = feature bytes). FlashWrite scratch cell
  moves accordingly, unchanged in address.
- **FlashWrite allowlist re-anchored to the NV/SAVE block** (`0x1EA000..0x1EB000`).
  Corpus-proven (all 118 OEM images) as the one always-writable free zone: OEM
  writes its region record at `+0x4B0` so the flash controller unlocks it, the
  head `0x1EA000..0x1EA4B0` is blank in every image, and the block is outside
  CMAC coverage. The retired `0x1ED000..0x1EF000` and `0x1D0000` windows were
  always-blank / never-OEM-written = controller-locked (writes didn't persist).

### Fixed
- **Host mirror was missing `Verb::FlashWrite` (`0x0A`)** — the drift-guard test
  didn't pin `0x0A`, so a host build could compile without a wire-id for it.
  Now added to the enum and the wire-values pin test.
- **Stale comment drift** — internal docstrings that described the feature-flag
  table as `8 bytes` (`0x00..=0x07`) or `flag[0x01..=0x07]` were carried forward
  from the pre-consolidation code; all corrected to `7 bytes` / `flag[0x01..=0x06]`.

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
- ABI codes are mirrored by `freemkv-unlock` and `hw-tester`.

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
