# Changelog

freemkv-firmware versions independently of the rest of the freemkv stack.
All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.2] - 2026-10-09

- Derive the DVD region from the drive's RPC mask alone: a drive whose mask
  prohibits nothing lists regions 1-8 instead of "Not set", and the info and
  inspection views share one formatter. An unset region state reads "Never set".
- Show the drive's original product code, factory date and country of
  manufacture from its production record instead of fixed placeholder rows,
  and drop the never-read LabelFlash/LightScribe rows.
- Use pioneer-optical 0.12.4 for the production record decoder.

## [0.11.1] - 2026-10-08

- Expand drive information with grouped Kernel/Normal identity, media capabilities,
  DVD region counters, and codec-driven read-only Quiet Drive/PureRead settings.
- Compact media capabilities into side-by-side CD/DVD and Blu-ray columns with
  adjacent read/write checkboxes; hide unknown and unsupported capability rows.
- Show current and saved Quiet modes together without duplicate values. Hide
  unsupported PureRead versions and child controls; keep editing disabled.
- Keep diagnostic log paths in the diagnostics window and show unset DVD regions
  explicitly instead of presenting their permission mask as a selected region.
- Use pioneer-optical 0.12.1 with hardened codec validation and Rust regression
  tests for malformed input, write restrictions, transport failures and UI state.

## [0.11.0] - 2026-10-08

- Remove the public `flash --force` option. Use the separate `recover` command for Pioneer recovery; normal Flash retains its backup and compatibility requirements.
- Add a Pioneer Recovery tab and `recover` command with a required Current firmware reference or explicit Read from drive, plus a Kernel + Normal target package.
- Recovery skips automatic backups, compatibility policy gates, and firmware readback. Receiver credentials come from supplied firmware code, with no model/key lookup table. Drives already reporting update mode skip update entry.
- Reject unsupported recovery drives before firmware reads or update commands, including dry runs.
- Preserve strict write failures and diagnostics; report success only after normal identity and readiness return. This recovery path has simulated-transport coverage, including PR1ML/207M packages, but has not been verified on the affected hardware.
- Allow unsigned Current reference backups to be decoded without requiring a transfer signature; target packages still require valid authentication.
- Include pioneer-optical dev updates for generic H8 firmware inspection and diagnostic memory transfers.
- Rename Flash firmware to Flash and align inspection source labels with their buttons.


### Added

- Inspect firmware packages or a captured Pioneer drive in a separate results
  window, including hardware family, Kernel and Normal metadata, UHD support,
  expanded regions and recognized text tables. Live captures also report DVD
  region and remaining change counters when available.
- Compare two packages, or a package and one drive capture. Results lead with
  hardware families, followed by per-component and per-region differences after
  alignment, with percentages and text/JSON export.
- Generic comparison consumes single-image facts from Pioneer Optical. It
  excludes established metadata and supported direct-reference relocations;
  constants, unproven address changes and unknown data remain differences.

### Changed

- Use Pioneer Optical 0.12.0's bounded single-envelope analysis API. Unsupported
  formats and incomplete analysis have explicit messages; comparison does not
  enter a firmware update session.

## [0.10.9]

### Fixed

- Pioneer backup no longer probes unrelated memory or assumes address zero is
  readable. Normal's location and size come from the captured Kernel's checksum
  and descriptor code. This fixes the 0.10.8 pre-flash backup failure on firmware
  that rejects reads below its exposed memory range, including BDR-212 firmware.
- Save validated captures before checking whether their components cover the
  proposed update. An incomplete capture remains on disk, while flash is refused.
- Refresh Pioneer OEM Kernel/Normal reconstruction metadata from the current
  firmware collection, including BDR-XD06U 1.11. Recognized firmware retains its
  OEM encoding key and signature instead of receiving zero placeholders.

### Changed

- Pin `pioneer-optical` to 0.11.3 for generic Kernel-derived backup layouts and
  precise layout validation error codes. Unknown or conflicting layouts are
  rejected before attempting a Normal read; no model-specific fallback is used.
- Add transport regressions for restricted read ranges, exact backup round trips,
  invalid Normal data, unsupported Kernel geometry and backup persistence ordering.
- Add a reproducible OEM-table generator that validates byte-exact reconstruction
  before admitting metadata, reports exclusions and preserves historical entries.
  Placeholder detection and raw encoding-key inspection use the library API.

## [0.10.8]

### Fixed

- Pioneer Kernel transfers use the decoded key and the receiver representation,
  correcting the derived-key transfer that could fail midway through a same-family crossflash.
- Normal transfers authenticate and send the same continuous representation,
  including recoverable envelopes with inserted file blocks.
- Receiver generation is recognized from firmware code rather than its editable marker.
- Cross-generation OEM restoration verifies the intermediate and final Kernel;
  a failed restore propagates an error instead of claiming the drive is working.
- Dump captures mark overlong replies incomplete and stop reads on transport loss.
- Backup layout checks distinguish firmware descriptors from incidental inquiry and log strings
  and incomplete descriptor copies retained after an update.
- Flash execution is announced only after final preflight checks. Forced warnings
  and failure messages distinguish refusal, transfer failure, and unverified completion.

### Changed

- Pin the shared SCSI transport to the stable `libfreemkv` 1.8.2 release.
- Pioneer validation and transfer preparation use published `pioneer-optical` 0.11.1,
  with stable error codes for diagnostics and future localized messages.
- Remove the model-specific transfer profile table and generated-prefix schedule.
- Pioneer diagnostic dumps include address-aligned memory, the dedicated log
  command, additional read surfaces, and a directory of captured and unavailable regions.
- Dump enables temporary RAM logging after capture when the receiver supports it;
  unavailable logging does not fail the dump.

## [0.10.7]

### Changed

- Drives are listed by the name the OS shows: the drive letter (`E:`) on
  Windows, `/dev/srN` on Linux and `diskN` on macOS while a disc is mounted,
  followed by the model, so identical drives can be told apart. The CLI `list`,
  the "multiple drives found" error, both desktop dropdowns and the flash
  confirmation all show it. Windows lists drives in letter order.
- Every command selects a drive by its name or its id (`\\.\CdRom1`,
  `/dev/sg3`, `ioreg:…`). `list` numbers are no longer accepted.

## [0.10.6]

### Added

- macOS CLI/GUI drive-open failures automatically collect bounded, process-specific Apple plug-in messages in the operation log and distinguish interface initialization failures from exclusive-access failures.

### Changed

- MediaTek `backup` now saves a 2 MiB `.bin` in the vendor's update format instead
  of a `.tar` archive. It reads every firmware byte, stores the boot page in its
  encrypted form, and replaces per-drive NVRAM settings, calibration and AACS
  revocation lists with factory contents. Backups carry no personal data and
  are byte-identical to the OEM update file for 180 of 186 known MT1959 builds;
  the rest differ only in the factory BD revocation list. `dump` still saves the
  raw drive read, including per-drive data.
- MediaTek `dump` retries a failed 4 KiB read as 512-byte pieces, so readable
  windows next to unreadable memory are kept.

### Fixed

- Restoring a 0.10.x MediaTek `.tar` backup no longer writes the boot page as
  READ BUFFER returns it (decrypted in place by the drive); the archive is
  rebuilt into the stored form before flashing. Backup refuses firmware whose
  boot page it cannot recognize.
- Windows lists every optical drive. Discovery probed only `\\.\CdRom0`–`15`,
  so drives with higher numbers (common after USB replugging) were missing; it
  now asks Windows for every CD-ROM device and optical drive letter, retries
  INQUIRY with 36 bytes for strict USB bridges, and logs each skipped device.

## [0.10.5]

### Added

- Firmware modifier CLI and GUI operations now create automatic detailed logs,
  including image fingerprints, integrity verdicts, modification reports, output
  publication and full error chains. The modifier desktop UI now matches the
  flasher’s layout, styling, background operations and diagnostic viewer/export.
- Modifier output is staged, synced and byte-verified before atomic publication,
  then checked again at the final path.
- Automatic diagnostic logs for CLI and desktop flasher operations, including
  platform/version, drive identity, SCSI commands, status/sense, transfer counts,
  timings, retries, native transport warnings and complete error chains.
  Command data is fingerprinted; metadata replies include bounded raw bytes.
  The desktop diagnostic viewer displays, copies and saves the same full log;
  failed operations also offer log export beside the error. No debug flag is needed.
- Logs are limited to 8 MiB per operation, retaining the initial context and recent
  events on rollover. Firmware transfer payloads are not logged.

### Fixed

- Validate MediaTek backup metadata using its response headers instead of treating
  allocation sizes as required lengths. Accept complete 24-byte serial descriptors
  and shorter INQUIRY replies, fetch longer metadata with bounded reads, and reject
  truncated or inconsistent descriptors. Logs include metadata bytes, requested/actual
  counts, decoded header lengths, follow-up reads, and validation outcomes.
- Require complete MediaTek preflight and fingerprint ROM reads, validate protocol
  probe descriptors, and recognize fixed-format sense with its valid bit set.
- Pioneer firmware access uses a four-byte probe and retries short responses up
  to twice, unlocking before each attempt. Explicit errors still stop the probe.
- Preserve no-medium sense errors on data transfers instead of reporting them as
  successful empty reads. Keep no-data readiness checks tolerant of an empty drive.
- Detect a disconnected Pioneer drive before subdividing failed recovery reads;
  record recovery errors and use a complete word for the liveness check.
- MediaTek firmware writes use strict status checks without automatic retries.
  Preserve completion errors and report failing write offsets and read-back gaps.
- Reject truncated drive identities and impossible transfer counts. Verify saved
  artifacts against captured bytes, including after publication to the final path.

## [0.10.4]

### Fixed

- Pioneer flashing no longer uses model/revision allowlists or exact UD04 image
  sizes. CLI and GUI validate envelope framing, component pairing, receiver
  authentication, integrity and hardware-family compatibility.
- Select the Kernel transfer schedule from its decoded layout: front-key images
  use linear FE chunks, derived-key images use the generated-block schedule.
  Wait for Kernel programming to settle before sending the Normal image.
- Read the control descriptor from the connected drive and derive its control
  word from the freshly captured receiver, with the universal word as fallback.
  The static controller-key catalog is now compiled only for historical tests.
- Resolve the supplied or installed Kernel before decoding Normal firmware,
  including family comparisons. Reject incompatible component tags before body
  decoding, and use the Kernel's receiver rules for integrity validation.
- Offline plans use the same generic envelope validation, with live control and
  installed-drive compatibility explicitly deferred until a device is available.

## [0.10.3]

### Fixed

- **macOS: `freemkv-flash list` found no drives on some Macs.** At attach,
  macOS files each optical drive under `IOBDServices`, `IODVDServices` or
  `IOCompactDiscServices`, chosen from the profile list the drive returns to
  GET CONFIGURATION. Drive discovery only looked under `IOBDServices`, so a
  Blu-ray drive that macOS had filed as DVD or CD (its profile list omitted
  the BD profiles, or the command failed and macOS fell back to CD) printed
  `drives: none found`, and its `ioreg:` selector could not be opened.
  libfreemkv 1.8.0 searches all three classes.
- **macOS 11 and older.** The macOS builds declare macOS 11 (Apple silicon)
  and 10.12 (Intel) as their minimum, but the drive layer called
  `IOMainPort`, which exists only from macOS 12. libfreemkv 1.8.0 no longer
  calls it.

### Changed

- libfreemkv 1.7.7 → 1.8.0 (SCSI transport only).

## [0.10.2]

### Added

- **Every platform freemkv ships on.** Each tool now has a Linux desktop app
  (`.deb` and AppImage, x86_64 and ARM64), Windows ARM64 builds, a per-tool
  Windows installer and portable zip, and static Linux CLIs for x86_64,
  ARM64 and 32-bit Raspberry Pi OS (armv7). Every GUI download carries its
  CLI, including the macOS `.app` for the Homebrew cask.
- **Package repositories.** The `.deb`s are served from the freemkv.org APT
  repository, and are repackaged as signed `.rpm` (Fedora, RHEL, openSUSE)
  and pacman (Arch Linux) packages for freemkv.org/rpm and freemkv.org/arch.

### Changed

- **pioneer-optical 0.10.** The flasher passes the 256-byte control buffer to
  `drive::enter_update` directly and writes through `Session::write(Role, …)`.
  The crate never sends a commit when a session is dropped, so a failed flash
  cannot commit a partial image. The separate `pioneer-codec` crate is gone.
- `--force` waives only the hardware-family gate; Kernel-tag refusals still
  apply, except that an unknown installed Kernel tag can be forced when the
  family matches. The warning says exactly what is being waived.

### Fixed

- **Linux GUI packages.** `freemkv-flash-gui` / `freemkv-fw-gui` `.deb`s now
  depend on `libxkbcommon-x11-0`, `libxcursor1`, `libxi6` and `libxrandr2`,
  which the windowing layer loads at run time under X11. Without them the GUI
  exited at start-up.
- A Kernel body of the wrong size is refused instead of silently skipping the
  marker patch, and the patch is applied only when the plan calls for it.
- A Kernel+Normal bundle with an empty Kernel tag is rejected. A Kernel-only
  partial backup validates, but a flash bundle still needs its Normal.
- `--recover` checks the Normal component's size and alignment before
  entering update mode, and the Bd update class is assumed only under
  `--recover`.
- A failed INQUIRY is reported instead of classifying the drive as
  unsupported.
- Text supplied by a drive or bundle is sanitized before it is printed.
- `dump` ends with a clear summary of any read gaps; salvage stops when the
  drive drops out, and its liveness probe re-reads the last good offset.
- Clearer recover advice and blocked-execution messages; broken intra-doc
  links in the Pioneer flash-plan module.

## [0.10.1]

### Changed

- Uses the published `pioneer-optical` from crates.io and `libfreemkv` from
  its GitHub tag; builds no longer need sibling checkouts, and every
  dependency resolves from the committed `Cargo.lock`.
- Pioneer bundles carry only the two component envelopes (no manifest); the
  flasher reads the drive identity back after a flash.

## [0.10.0]

### Added

- **Pioneer flasher.** Backup-first flash of Pioneer BD drives through
  `pioneer-optical`, gated on a hardware-family match between the installed
  and target firmware and on the installed Kernel tag. Cross-flash between
  editions of the same family; Kernel downgrade via the decoded-body marker
  patch.
- `dump` / `dump --force` and `flash --recover`.

## [0.9.2]

Feature release: unifies UHD and BD acceptance under a single lever
(`Feature::Unrestricted`) and adds a new 9th lever that widens the drive's
post-classification state-band gate at `0x00136826`. Fixes silent
`0x30/0x02 Incompatible medium` refusal on triple-layer UHDs whose disc
descriptor drives the mode-0 arm of `f_84996`, causing the state byte at
`0x01ff9e04` to land on the `0xE*` band that the OEM `cmp (state>>4),#0xC`
gate refuses. Golden KAT re-blessed once (deliberate) to cover the injected
stub bytes.

### Changed

- **`Feature::Uhd` renamed to `Feature::Unrestricted`.** Same numeric
  discriminant (`0x03`), same behaviour on the UHD arm — this rename
  documents the intended semantic: one flag controls all AACS media
  acceptance (BD, UHD, and now the state-band gate). The wire ABI byte is
  identical; existing hosts continue to interoperate. `Feature::Bd` (`0x04`)
  is preserved for round-trip and is now marked
  `#[deprecated(since = "0.9.2")]` — `SET`/`GET` on `Bd` still round-trip via
  its own NV slot.
- **`thumb-asm` bumped `0.11.1` → `=0.13.0`.** Test-only / no behaviour
  change on the encoder API. 0.12.0's `#[non_exhaustive]` widening and
  Target-parameterised decoders don't attach here; 0.13.0's flag-liveness +
  CBZ-relocate APIs aren't reachable from the MT19xx stubs. Integer-overflow
  hardening in `Asm::finish` / `CommandTable::find` /
  `analysis::function_start` / `isa::disassemble` takes effect automatically.

### Added

- **New lever `Feature::Unrestricted` → auth-cell state-band widen at
  `0x00136826`.** Resolves the OEM `cmp (state>>4),#0xC; bne <6F/02>` gate
  via the extended `AUTH_CELL_SIG` (7 halfwords anchored on the pc-relative
  `ldr r4, [pc, ...] = 0x01FF9E04`; UNIQUE on BU40N 1.00). The stub, emitted
  by `Mt1959Engine::build_authcell_widen_stub`, widens the accepted top-nibble
  set when armed and replays OEM byte-for-byte when off. Wired last in the
  Raw Read lever emission order so the stub sits at the end of the injected
  band. `CreateReport` gains `auth_cell_site` + `auth_cell_stub_va` (zero
  when unwired — e.g. on MT1939 classic, where the anchor shape doesn't
  exist).
- **Structural audit coverage for the auth-cell widen `bl`.** `audit.rs`
  adds an `auth_cell_site` + `auth_cell_stub_va` fact pair check, matching
  the shape used by the UHD / BD / HRL detours.

### Fixed

- Silent `0x30/0x02 Incompatible medium installed` refusal on a specific
  triple-layer UHD (observed on a BU40N 1.00 fw-flashed drive):
  the drive-side disc classifier lands `[0x01ff9e04]` on `0xE8` for this
  disc (top nibble `0xE`) instead of the usual `0xC*`, which the un-hooked
  OEM `cmp` at `0x00136826` refused. Static analysis (three parallel
  passes) confirmed all 100 writers of `[0x01ff9e04]` are byte-identical
  between OEM and modified builds; the fix widens the gate itself under a
  flag rather than touching the classifier.

## [0.9.1]

A dependency-correctness release: no behavioural change to any lever, but the
emitted code is now correct by construction where 0.9.0 was correct by
coincidence. Hardware-validated 0.9.0 images remain sound — see below.

### Changed

- **Branch installs go through `thumb_asm::install_branch`.** `install_guard.rs`
  no longer hand-rolls its decode-back assertions; it keeps only the anyhow
  re-flavouring of the crate's typed `InstallMismatch` (plus
  `assert_literal_absent`, which has no upstream equivalent), exactly as that
  file's own 0.9.0 header comment said to do once a framework-agnostic
  equivalent landed upstream. `AkeInstallShape` is retired in favour of
  `thumb_asm::BranchKind` — it was that enum under a different name.

  The AKE install site is the reason this matters. It used to match on the
  install shape to pick an *encoder*, write the bytes, then match on the shape
  again to pick a *decoder* to verify with — two matches that could disagree.
  A shape/guard disagreement is precisely the 0.8.13 BL-over-tail-call bug:
  installed as `BL`, and nothing checked it should have been `B.W`.
  `install_branch` encodes, writes and verifies against one `BranchKind`, so
  the two cannot drift. Byte-neutral: the golden KAT and both AES-CMAC digests
  are unchanged.

### Fixed

- **`mov_reg` now emits a real `MOV (register)`, not a flag-setting `ADDS`.**
  Upgrading `thumb-asm` from 0.1.0 to 0.10.0 (0.1.0 has been yanked upstream)
  corrects an encoding bug in the assembler: `Asm::mov_reg` was emitting
  `0x1C00|…` — `adds rd, rm, #0` — which clobbers the condition flags and
  cannot address r8–r15. It now emits the architectural `MOV (register)` T1,
  `0x4600|…` (ARM ARM A7.7.77). Upstream added `movs_reg` for callers that
  actually wanted the flag-setting form; nothing here does.

  This changes exactly 21 emitted bytes across the injected handler, all of
  them the high byte of a `mov_reg` halfword (12x `1c29→4629`, 6x
  `1c28→4628`, 2x `1c04→4604`, 1x `1c31→4631`) — same image length, same
  registers, verified byte-for-byte to contain no other encoding change. The
  golden KAT and its two AES-CMAC digests were deliberately re-blessed.

  Shipped 0.9.0 images are not at risk: all nine `mov_reg` sites use low
  registers and none reads the flags afterwards, so the stray `adds` was
  inert there. The new encoding is correct unconditionally rather than by
  coincidence, which is the reason to take it.

## [0.9.0]

First public release since 0.8.3. Consolidates the 0.8.4–0.8.14 development
line: the `Encryption` flag-set consolidation, the boot-time de-bus fix, the
`thumb-asm` extraction, and a flasher hardening pass. Hardware-validated on
BU40N 1.00 — empty-tray base certification 59/59, and a UHD disc run proving
de-bussed reads end-to-end (every sampled unit opens with the AACS unit key).

**Consumers must update**: the `Ake` (`0x06`) + `Bus` (`0x07`) feature pair is
retired in favour of a single `Encryption` (`0x06`) lever. Wire id `0x07` no
longer exists. `freemkv-unlock` 1.7.5 carries the matching change.

### Changed
- **Every Thumb primitive now comes from the standalone `thumb-asm` crate.**
  `crates/freemkv-fw/src/thumb.rs` collapsed to a thin shim over
  `thumb_asm::*` plus the anyhow-flavored install-guard helpers in
  `install_guard.rs`. Byte-for-byte identical emit verified (image sha256
  pre- and post-migration match). Now consumed from crates.io.
- **`Feature::Ake` + `Feature::Bus` retired into one `Feature::Encryption`.**
  Six flags total. `0x00` = every drive-side encryption/cert requirement
  relaxed; `0xFF` = OEM passthrough; `0x01` = on. Wire id `0x07` (`Bus`) is
  retired — empirically inert as a separate datapath lever on BU40N/MT1959,
  since the single `Encryption` lever de-busses on its own.
- **Boot-init site resolved once per build.** New `resolve_boot_init_pair`
  is the single source of truth for the detour `(conv, orig_init)` pair;
  `resolve_boot_init_site` and `emit_boot_init` both consume it, eliminating
  a redundant second `find_boot_init` image scan on every create/modify.

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
- **`SET Encryption` no longer fires the AACS session-rearm wrapper.** The
  0.8.13 revert primitive called the OEM rearm wrapper from the vendor-CDB
  SET handler whenever `Encryption` moved to a non-off state. An image-wide
  branch scan proved the OEM only ever reaches that wrapper from its
  cold-boot init path — there is no medium-gated caller, and its VA is not
  present as a call-target literal anywhere in the image. Firing it from a
  vendor-CDB context couples its `aacs_session_reset` + subsystem re-init
  side-effects into the shared engine datapath, which wedged every
  subsequent vendor CDB on a drive with no medium loaded (SCSI errors on
  all following GETs, persisting for the session). The AKE detour already
  handles both directions of the flag in software on the next data read,
  and the drive re-arms bus-encryption itself on disc insert, so `SET` now
  only records the flag. Verified on hardware: base certification went
  54/5 → 59/0, and a UHD disc run returns every sampled unit de-bussed.
- **Flasher refuses to report success on ambiguity.** `wait_ready` now bails
  after 45 s instead of looping forever; post-settle sense hard-fails on
  MEDIUM/HARDWARE/ABORTED and warns (rather than silently swallowing) on an
  unparseable or errored reply; unverified read-back chunks and a failed
  firmware-identity read-back both bail instead of printing and continuing.
  `--allow-crossflash` now refuses when the drive's current firmware cannot
  be identified. Drive classification requires the `MT19` boot banner at
  `0x003000` in addition to the GET CONFIG `0x010C` echo, so a compliant
  non-MTK drive can no longer be misclassified as MediaTek. Tar dump members
  are length-checked and capped at 256 KiB before allocation, and the
  medium-status guard re-probes immediately before `flash_open` to close a
  preflight→open TOCTOU window.

### Security
- **Emit-time absence guard for the rearm wrapper.** `assert_literal_absent`
  refuses to ship an image whose injected handler contains the AACS
  session-rearm VA as a Thumb-tagged call-target literal, so a future
  refactor cannot silently reintroduce the vendor-CDB wedge described above.

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
- ABI codes are mirrored by `freemkv-unlock`.

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
