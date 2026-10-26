# Changelog

Customer-visible changes to freemkv Flash and freemkv Modify, newest first.
Versions are independent of the freemkv ripping applications.

## [0.15.4] - Unreleased

### freemkv Modify

- Add component-based MediaTek UHD conversion planning and offline hook tests.
  Preserve native hardware defaults and refuse incomplete conversions; this
  development work does not enable classic UHD support yet. Bind the classic
  DI detour to its native frame, format switch and layer normalization; validate
  OEM replay and U/5 recognition on all 24 classic inputs with CPU execution.
  Bind routing callers to balanced native stack/LR contracts and verify saved
  parent returns. Keep the internal signed placement probe gated from user tests.
  Bind the reverse gate to its native rejection graph and CPU-test both native
  calculations while preserving legacy calibration policy.

- Add classic MediaTek read-speed control using the native default selector and
  native read maximum. Preserve OEM behavior and hardware/media limits; refuse
  disconnected, ambiguous or impure selector paths. Validate four native forms
  with independent CPU execution and require a caller-preserving tail branch.

- Make native BD hooks read the shared Unrestricted runtime flag, matching UHD
  and auth hooks. The retired BD storage slot no longer changes new hook behavior.

- Implement all three auth-hook choices where native refusal is proven: OEM
  replays its decision, On allows access, and Off takes its refusal path.
  Preserve registers, stack and comparison flags; keep older partial records
  restricted to their original choices.

- Distinguish decoded constant-success checks from helper calls in receiver
  analysis, preserving explicit bypass evidence and rejecting unknown effects.

- Recover allocation-limited OEM builds using erased space only when native
  receiver, programming and integrity contracts prove a safe coverage extension.
  Preserve integrity descriptors outside that plan and honor explicit settings
  after retry; retain refusals for unproven receiver contracts.

- Select media, VID and auth-cell implementations from shared OEM code-layout
  evidence. Add the WH register contract and preserve unavailable-hook reasons.
- Offer only boot values implemented by the generated hooks. Widening can offer
  On/OEM without advertising an unimplemented native-media refusal mode.
- Report classic boot hooks already emitted by the engine, exposing the actual
  editable controls instead of silently hiding them.
- Allocate finalized code and settings records at their exact size, retaining
  alignment, protected-region and integrity-coverage checks. Add exact-fit,
  one-byte-short and atomic-refusal regressions, including tight BU40N 1.05.
- Share the CDB handler's reset-defaults body with erased-NV fallback to recover
  28 bytes without removing commands. Preserve older settings records; new
  compact records remain editable and are checked by independent CPU tests.
- Query hash-bound capabilities through the real Modify preview and structural
  audit, including explicit unsupported results for publication tooling.
- Execute hook state/register/stack contracts on an independent ARM CPU in CI.
- Keep descriptor-pattern candidates separate from proven BD controls, avoiding
  a refusal detour on an unrelated structure-response path.
- Add a source-hashed MT1939 WH14NS40 investigation with native routing and
  paired classifier CPU tests. Retain the existing alternate path in the
  research trampoline; classic UHD remains unavailable pending complete proof.

### freemkv Flash

- Standardize Pioneer CDB response parsing in the optical library and select
  one backend from protocol evidence. Remove duplicated SAT/REC support lists
  from backup and envelope reconstruction. Preserve captured firmware without
  OEM seeds/signatures and label reconstructed metadata honestly; receiver and
  compatibility checks still authorize each particular flash.

- Update the shared MediaTek dependency to the source-pinned analysis release;
  firmware hook analysis remains an opt-in image feature.

## [0.15.3] - 2026-10-25

### freemkv Flash

- Explain MediaTek firmware read restrictions before Flash, Backup and Dump.
  Explicitly rejected backup reads are an expected limitation, with no firmware
  write, rather than a generic connection failure or automatic report request.
  Incomplete diagnostic dumps remain clearly unsuitable for restoration.
- Show DVD region reset counters and lock state only for RPC-2. RPC-1 reports
  region-free status without presenting its zero fields as exhausted budgets.
- Correct disconnect classification, unsupported-comparison severity, backup
  reconstruction limitations and no-backup guidance after a personal review of
  every error catalogue entry and the operation/confirmation boundaries.
- Add the shared, compiled-in settings adaptation framework and independent
  original-hardware checks. The production profile registry is empty: supported
  firmware transitions and website crossflash decisions are unchanged. Synthetic
  tests cover exact matching and UD02-only stock-return prerequisites.

### freemkv Modify

- Show only relevant region information when inspecting a drive after applying
  Region-free. No firmware hook behavior changes in this release.
- Align website feature listings with each exact image's Modify capability
  report. Engine family and native UHD support no longer imply an available
  UHD/BD modification. WH16NS58 1.V9's unavailable combined control is no longer
  advertised as supported.

## [0.15.2] - 2026-10-25

### freemkv Modify

- Allocate injected MediaTek code outside integrity metadata, update signatures,
  identity and drive-owned storage, even when those areas are erased. Preserve
  integrity-table descriptors and unused slots in the structural audit. This
  fixes the reproduced WH16NS58 1.V9 table corruption during modification.
- Remove the separate Sign action. Modify signs and verifies generated firmware
  automatically. The CLI command is now `modify INPUT [OUTPUT]`; existing
  `create` scripts remain compatible.
- Treat an already-enabled modification, including DE, as a successful no-op.
  Other unavailable features remain listed as skipped.
- Apply the independent classic MediaTek HRL change even when the raw-read
  patch is unavailable, restoring consistent output for BE14NU40 1.01.

### freemkv Flash

- Reject overwritten MediaTek integrity-table metadata before flashing, even
  when the stored region hashes match. Modify also rejects these damaged inputs.

- Distinguish information, actions the user needs to take, and failures. Give
  specific guidance for permissions, missing selections, unsupported operations
  and known transfer failures without presenting routine restrictions as faults.
- Include the exact firmware files used by an update in its diagnostic archive,
  including the selected Current and Target files when available. Record missing
  inputs explicitly and include filenames and SHA-256 hashes in notification
  emails so reports can be reproduced.

- Check for a newer stable release at startup. When confirmed, explain the
  update and disable automated diagnostic submissions until updated; failed
  checks allow normal use, and local logs remain available.
- Show known transfer failure causes alongside the unverified-update warning,
  without repeating the full error in the single-line status.

- After a fully verified flash without an attachment, ask whether a diagnostic
  report is needed and suggest confirming success on the website.
- Require a nonblank description when submitting a diagnostic report, and include
  the description in the maintainer notification email.

## [0.15.1] - Unreleased

### freemkv Flash

- Give clearer guidance for corrupt or incomplete firmware files.
- Show more precise drive hardware and firmware details.

## [0.15.0] - Unreleased

### freemkv Flash

- Keep file inspection in a bounded background queue, reuse translated analysis,
  and release obsolete controls and incomplete diagnostic archives.
- Report desktop log, clipboard and confirmation failures in the selected language;
  keep diagnostic actions available after file-origin inspection.
- Prevent a Windows crash when an active operation displays its close warning
  while background progress arrives.
- Retain completed dump and backup attachments for diagnostic submissions. Ask for
  an optional description, verify the attached bytes, and confirm exactly what was
  sent after submission succeeds.
- Keep firmware confirmations concise, with technical information under Details.
  Show saved backup evidence, all warnings and a fresh risk acknowledgement.
- Reject unusable recovery targets before a long drive capture. Explain when a
  valid update does not match the installed firmware, without calling it corrupt.
- Use the available freemkv command for MediaTek raw dumps, inspect MediaTek release
  packages, and report incomplete reads without guessing a permanent restriction.
- Report Pioneer Kernel-only backups as partial, and avoid repeating the same
  target validation before authorization.
- Recognize genuine MediaTek boot responses that include machine code after the
  identity label, restoring supported non-Pioneer drive profiles. A failed foreign
  vendor probe no longer hides a valid native protocol response.
- Keep firmware file pickers usable for unrecognized and dump-only drives. Never
  pass an empty filter to the operating system, and show localized guidance when
  a native file dialog cannot complete. Native QA now opens and cancels all four
  firmware pickers with both supported-format profiles and an unsupported profile.
- Keep prepared recovery firmware in memory through confirmation, avoiding another
  complete drive read when recovery starts. Check the connected drive again before
  writing and retain independent verification after the update.
- Show reading, writing, restart and verification status for both supported drive
  protocols, with measured percentages where available and a waiting indicator
  while the drive restarts.
- Explain incomplete Current firmware and other operation problems in the selected
  language, including whether firmware was written and the next action to take.
- Check incompatible supplied Current and target files before reading the drive.
  When Current comes from the drive, keep the existing backup-first checks.
- Use the selected language for command-option errors in both command-line tools.
- Keep the same clear error and write-status guidance in packaging, offline
  analysis, verification refusals and interrupted desktop operations.
- Keep backup refusals and confirmation prompts in the selected language.
  Distinguish a failed drive read from an incomplete selected Current firmware
  file, and use the same risk guidance in Flash and Recovery.
- Require a usable Pioneer backup without offering an impossible bypass. Preserve
  permission, connection and Current-file causes, and keep log-failure details in
  fallback diagnostics. Confirmation answers also support the selected language.
- Give specific guidance for unsupported or malformed firmware files and existing
  backup destinations, with clear next steps for inspection and recovery refusals.

## [0.14.5] - 2026-10-23

### freemkv Flash

- Recovery can explicitly bypass the Pioneer firmware family check. The option appears only after a proven family mismatch. Selecting it opens a translated risk warning and requires typing a fresh five-digit code; wrong submissions close the popup, and consent is consumed by one attempt. Recovery skips Flash-only tray checks on its update and restoration passes; normal Flash remains family-checked and refuses a loaded disc. Recovery still requires its final write confirmation and verifies the firmware afterward. Changing the selected drive or firmware clears the override. CLI Recovery exposes `--bypass-family-check` with the existing mandatory write-risk acknowledgment.

- During explicit Pioneer Recovery, unsupported inserted media (`02/30/00`) now advances from readiness polling to the existing target identity, exact Kernel readback, and Normal readback checks. This status alone never counts as verification; normal Flash and other readiness failures remain unchanged. A hardware trial on one UD02 unit with unreadable UHD media inserted confirmed the target and matched both Kernel and Normal readbacks.

- Identify Pioneer and MediaTek drives from validated protocol responses, independent
  of vendor/model branding. ASUS SBC-06D2X-U and other OEM-branded Pioneer drives
  now reach the same backend; conflicting signatures are refused.
- Preserve native SCSI sense codes during read-only protocol probes so unsupported
  commands remain distinguishable from transport failures.
- Share read-only discovery across normal and recovery flows. Preserve transport
  errors and Current-assisted recovery for loaders with incomplete identity.
- Use matching protocol-evidence APIs in pioneer-optical 1.0.4 and mediatek-optical
  1.0.1, keeping recognition separate from receiver and family checks.
- Suggest supplying Current firmware when a Pioneer current-firmware capture fails.

- Verify Pioneer updates by exact firmware readback and startup instead of requiring
  package branding to match the device name. Use pioneer-optical 1.0.4 for the shared
  Flash, Recovery, Normal-only and Kernel-restoration verification paths.
- Retain separate Kernel, Normal and startup results in failure messages, alongside
  the selected package and observed device identity.
- Share hardware-family comparisons across inspection and admission checks. Different
  fingerprint schemes are not comparable; missing identifiers never count as equal.
- Report exact contents, naming differences and version direction separately in
  comparison results. Only order numeric revisions within the same firmware edition;
  retain unknown and incomparable results for unrelated or opaque revision labels.

## [0.14.4] - 2026-10-23

### freemkv Flash

- Show CLI drive information in grouped, aligned sections using the same identity and capability fields as the GUI. Keep native transport traces in diagnostic logs instead of flooding the terminal.
- Accept standalone BIN files and TAR packages for MediaTek in both Flash and Recovery. Pioneer updates continue to require TAR packages. File pickers and validation now share the same backend format rules.
- Use pioneer-optical 1.0.2 to analyze compressed and uncompressed firmware consistently for hardware families, UHD capability and Kernel ABI requirements.
- Track Pioneer FE9F interface setup as a family signal, including explicit zero-valued register initialization writes.
- Restore matching between BDR-S08 and BDR-S11JX SAT 8800 firmware whose equivalent servo rows were stored in different regions or orders. Distinct SAT 8801 board evidence remains separate.
- Reject unresolved compressed firmware evidence instead of scanning compressed bytes as instructions. Hardware-family catalogs use the new `pioneer.hardware.v3` scheme.

## [0.14.3] - 2026-10-23

### freemkv Flash

- Allow raw dump attempts on Pioneer REC drives and other valid Pioneer hardware identities previously reported as Unknown. Actual read coverage depends on the drive; unreadable regions remain recorded in the dump.
- Offer Save raw dump when an OEM backup is unavailable or a backup attempt fails.
- Submit a completed dump or backup with diagnostic logs and session history using Submit Dump or Submit Backup. Uploads require browser approval.
- Recognize 32 additional Pioneer SAT firmware images when reconstructing OEM backups. ATA, SCSI and REC OEM backup construction is not yet supported.

## [0.14.2] - 2026-10-22

### freemkv Flash

- Include servo coefficient evidence when matching Pioneer hardware families, including boards that previously skipped it. This separates firmware patterns formerly grouped together, including SAT 8000 versus 8680.
- Use pioneer-optical 1.0.1 for both firmware selection and receiver family gates.
- Report flash failure milestones and localized error outcomes consistently across frontends.

### freemkv Modify

- Preserve specific integrity-verification guidance and report background worker failures in diagnostic logs.

## [0.14.1] - 2026-10-21

### freemkv Flash

- Ask whether to proceed when a backup cannot be made, including the normal read restrictions on many MediaTek drives. Choosing Yes still requires final confirmation before flashing.
- Require a Current firmware file when the drive cannot provide its installed firmware automatically. Flash and Recovery show the same controls for the selected drive.
- Translate operation forms, confirmations, results and error guidance in all 29 UI languages. Diagnostic logs remain in English.
- Show concise errors with a next step, while keeping command details and full failure causes in diagnostic logs.
- Put View Log, Save Log and Submit Report together in one row, and remove repeated operation labels above the tabs.

### freemkv Modify

- Add a saved language preference and translated controls, startup settings, results and error guidance in 29 languages. Diagnostic logs remain in English.
- Restore missing Raw Read patching and HRL/encryption startup options when modifying WH16NS58 1.V9 firmware.

## [0.14.0] - 2026-10-21

### freemkv Flash

- Add a saved language preference and initial translations for common controls and menus in 29 languages. Translation of operation details and error messages is still in progress.
- Show the correct application version in macOS app information.
- Fix misleading Pioneer errors for unrecognized MediaTek TAR files. Invalid packages now report a package error before any write.
- Let MediaTek Flash use a selected Current firmware file when the drive blocks automatic detection. Read from drive remains the default; failed detection now explains how to select the installed firmware.
- Give Flash and Recovery matching firmware-selection layouts, with Read from drive selected by default in both desktop forms.
- Make MediaTek Recovery consistently use the Current firmware file you select and report when it does not match the drive.
- Clearly distinguish a blocked precheck from a failed update, and show when no firmware was written.
- Explain incompatible hardware using the installed and target firmware models, with technical identifiers kept in diagnostics.
- Make Pioneer previews clear that passing package checks still requires a drive compatibility check before writing.

### freemkv Modify

- Fix firmware creation and editing startup settings for WH16NS58 1.V9 and other affected firmware.
- Explain when an input is already modified and a clean OEM firmware file is required.

## [0.13.4] - 2026-10-20

### freemkv Modify

- Choose firmware startup settings in the desktop app or with the CLI's repeatable `--default FEATURE=VALUE` option. The selected settings apply every time the drive starts.
- Reset startup settings to the standard defaults: unrestricted disc access On, with HRL, encryption, speed and region at OEM behavior.
- Reopen newly created BIN or TAR files to edit their startup settings. Older modified images still require their original OEM source.
- Switching or reselecting an image now reloads that image's settings, so choices from a previous file cannot carry over accidentally.
- Unsupported settings are explained before creation. Use `--dry-run` to preview the result without writing an output file.

### freemkv Flash

- Preview Recovery's planned transfers, including any temporary firmware and restoration steps, before confirming a write.
- Flash and Recovery results are easier to follow, with a concise status and direct View Log and Submit Report actions.
- Save session history and operation logs automatically. Detailed errors remain available for viewing and export even when file logging fails.
- Cancel a report submission, and avoid indefinite waits when the reporting service is unavailable.
- Fix Pioneer Recovery downgrade preparation for the reported WX1DM `0000` to S12JX 1.03 case. A failed restoration is reported explicitly.
- Fix preparation of the MediaTek INTM to 1.V9 transition while preserving the drive's boot region. Physical-drive confirmation of this transition is still outstanding.
- Improve recognition of Pioneer-based PLEXTOR and TEAC firmware and avoid false revision mismatches.
- Clear stale results when the selected firmware or drive changes. Incomplete verification and temporary firmware states are reported clearly.

## [0.13.3] - 2026-10-19

### freemkv Flash

- Fix the preflight refusal reported when changing a Pioneer BDR-207M from 1.60 to BDR-PR1ML 1.30.
- Prepare the drive's startup setting for the target firmware in both Flash and Recovery. A failed setting change stops before firmware transfer.
- Recovery from an already-running loader continues without attempting settings commands that require normal drive operation.

## [0.13.2] - 2026-10-19

### freemkv Flash

- Prepare Pioneer startup settings for compatible firmware changes, including the reverse transition.
- Report the last observed readiness and identity when a drive does not return to normal operation after Flash or Recovery.
- Recovery from an existing loader no longer attempts unsupported persistent-settings commands.
- Physical-drive confirmation of the supplied S12JX/WX1DM transition remains outstanding.

## [0.13.1] - 2026-10-19

### freemkv Flash

- Complete paired MediaTek updates through restricted intermediate firmware, rechecking the drive before the final transfer.
- Select an optional Current firmware reference and its TAR member in MediaTek Recovery. A stale reference is rejected when intermediate firmware is already running.
- Report limited verification when a drive cannot provide protected readback. Write failures and readback mismatches still stop the operation.
- Recognize additional Pioneer-based drives without relying on an exact product-name list.
- Restore supported Pioneer backups with missing signatures and accept the reported WX1DM 1.01 backup layout. Original backup files are preserved.
- Show whether selected firmware is likely OEM, user-provided or of unknown origin. This information does not establish compatibility.

## [0.13.0] - 2026-10-16

### freemkv Flash

- Improve MediaTek Flash and Recovery preparation for drives running normal firmware, intermediate firmware or their boot loader.
- Improve diagnostics when Recovery preparation fails.
- Fix Pioneer transfer preparation when a package includes a replacement Kernel.
- Keep tabs and controls accessible when a drive's profile is unsupported or unavailable; each operation explains whether it can proceed.
- MediaTek Recovery remains experimental and requires physical-drive validation.

## [0.12.5] - 2026-10-16

### freemkv Flash

- Add experimental MediaTek Recovery, including drives that cannot supply a Current reference or rollback backup.
- Accept MediaTek release TAR packages, including declared intermediate-to-final updates. Stop if the intermediate firmware does not start correctly.
- Accept standalone BIN files for Flash and Recovery. A BIN writes only the supplied image; it does not add intermediate firmware.
- Add `package` to wrap a BIN as a single-image TAR.
- Choose transfer encoding automatically and refuse unknown or conflicting receiver information.

### freemkv Modify

- Modify firmware inside MediaTek release TAR packages. Preserve the intermediate image and write the changes only to the final image.

## [0.12.4] - 2026-10-15

### freemkv Flash

- Allow valid MediaTek intermediate firmware as the source or target of a compatible update.
- Improve failure messages when a firmware identity, readback region or restored backup cannot be verified.
- Keep drive-reported model, revision and serial information available when other metadata cannot be read.

## [0.12.3] - 2026-10-14

### freemkv Modify

- Stop with a clear message and no output file when an image has no applicable changes. Already-modified images are identified explicitly.
- When only some modifications apply, show which succeeded and why the others are unavailable.

### freemkv Flash

- Correct the displayed MediaTek generation for affected LG and ASUS drives. Existing backups with the older label remain usable.
- Explain when a MediaTek drive does not expose enough firmware for backup. Add the read-only `dump --read-map` diagnostic for support.
- Report drive-command rejections accurately, instead of describing every rejection as a connection failure.
- Fix Pioneer Kernel transfers that could fail while recovering between the BDR-205 and BDR-206 families.
- The CLI can proceed without a rollback backup when the drive hides its firmware and the operator explicitly confirms the risk. This option is unavailable in the desktop app or unattended operation.
- Back up MediaTek drives already running freemkv firmware even when their stock firmware did not expose its flash.

## [0.12.2] - 2026-10-14

### freemkv Flash

- Restore compatible Pioneer cross-model updates that 0.12.1 incorrectly refused, including BDR-UD03 to BDR-UD04.
- Keep normal Flash refusals for firmware that requires a different receiver encoding, and direct those cases to experimental Recovery.
- Recovery re-encoding remains unconfirmed on hardware.

## [0.12.1] - 2026-10-14

### freemkv Flash

- Refuse Pioneer updates that the installed firmware cannot receive or that would make the saved backup unusable.
- Add experimental Pioneer Recovery for supported same-hardware firmware transitions that normal Flash refuses. Physical-drive acceptance of the re-encoded firmware is not yet confirmed.
- Allow compatible MediaTek cross-model updates within the same hardware family. Different or unknown hardware families are refused.

## [0.12.0] - 2026-10-10

### freemkv Flash

- Fix MediaTek backups on MT1939 drives, including LG BH14NS40 and BE14NU40, that previously failed with an unrecognized boot page.
- Identify known OEM firmware in backups, Inspect and Compare. Reconstructed backups are labelled separately.
- Refuse raw drive dumps as flash inputs when their boot page would not start the drive.
- Show corrupt MediaTek integrity data as invalid, and improve chipset information.
- Use a native desktop interface on macOS, Windows and supported Linux systems.
- Save the pre-flash backup before asking for final confirmation. Cancelling retains the backup and writes no firmware.
- Require an explicit risk acknowledgement before enabling the confirmation button. Enter and Escape cancel the dialog.
- Make Recovery available for recognized receivers even when normal drive classification is unsupported.
- Improve comparison results by separating expected per-drive differences from unexpected firmware changes.

## [0.11.2] - 2026-10-09

### freemkv Flash

- Show DVD regions 1–8 when the drive permits all regions, and distinguish an unset region from a selected region.
- Show the original product code, factory date and country of manufacture when available.

## [0.11.1] - 2026-10-08

### freemkv Flash

- Expand drive information with firmware identity, media capabilities, DVD region counters and supported Quiet Drive/PureRead information.
- Make capability details easier to compare and hide unsupported or unknown rows.
- Show current and saved Quiet modes together, and keep diagnostic log locations visible.

## [0.11.0] - 2026-10-08

### freemkv Flash

- Add a separate Pioneer Recovery tab and `recover` command. Normal Flash continues to require its backup and compatibility checks.
- Remove `flash --force`; use Recovery for supported drives that cannot complete a normal update.
- Recovery accepts a Current firmware reference or an explicit read from the drive. Unsupported drives are refused before update commands.
- Recovery reports success only after normal drive identity and readiness return. This does not establish byte-for-byte readback, and the reported PR1ML recovery remains unconfirmed on hardware.
- Add Inspect for firmware files and captured drives, plus Compare with text and JSON export.
- Explain unsupported files and incomplete analysis without entering update mode.

## [0.10.9]

### freemkv Flash

- Fix Pioneer pre-flash backups that failed on drives with restricted firmware reads, including the reported BDR-212 case.
- Save usable captures even when they do not contain enough information to authorize the proposed update.
- Recognize additional OEM firmware, including BDR-XD06U 1.11, when reconstructing backups.

## [0.10.8]

### freemkv Flash

- Fix Pioneer transfers that could fail partway through a compatible crossflash.
- Report failed OEM restoration instead of claiming the drive is working.
- Mark incomplete dumps clearly and stop recovery reads when the drive disconnects.
- Distinguish a refused update, a transfer failure and an update whose completion could not be verified.
- Include more available diagnostic information in Pioneer dumps; missing optional logging does not fail the dump.

## [0.10.7]

### freemkv Flash

- Identify drives using the names shown by the operating system, including Windows drive letters, so identical drives are easier to tell apart.
- Select a drive by its OS name or device ID. Numbered entries from `list` are no longer accepted as selectors.

## [0.10.6]

### freemkv Flash

- Save MediaTek backups as 2 MiB BIN files in update format, with per-drive settings and calibration replaced by factory contents. Raw `dump` output still contains per-drive data.
- Fix restoration of older MediaTek TAR backups. Unrecognized boot pages are refused.
- Keep readable data next to failed regions when dumping MediaTek firmware.
- Find Windows optical drives that were previously missing, including devices with high system-assigned numbers and strict USB bridges.
- Give more useful diagnostics when macOS cannot open a drive or obtain exclusive access.

## [0.10.5]

### freemkv Flash and Modify

- Create detailed operation logs automatically, with options to view, copy and save them from the desktop apps.
- Keep useful error details available after failed operations without requiring a debug option.
- Limit log size and omit firmware transfer payloads.
- Verify newly saved files before reporting success.
- Accept valid short MediaTek identity replies while rejecting truncated metadata and incomplete reads.
- Improve Pioneer probing and stop recovery reads when the drive disconnects.
- Preserve drive errors during transfers and report failed writes and incomplete readback clearly.

## [0.10.4]

### freemkv Flash

- Recognize compatible Pioneer firmware without the former UD04/S09 model restrictions.
- Fix Pioneer transfer preparation and refuse incompatible firmware components before writing.
- Improve desktop drive information, backup, dump, file checking and flash progress.
- Keep replacement-backup confirmation consistent between the CLI and desktop app.
- Downloads cover macOS Intel/Apple silicon, Windows x64/ARM64 and Linux x86_64/ARM64. Linux ARMv7 is CLI-only.

## [0.10.3]

### freemkv Flash

- Find optical drives on Macs that previously reported no drives, including Blu-ray drives listed by macOS as DVD or CD devices.
- Restore drive access on supported macOS versions older than macOS 12.

## [0.10.2]

### freemkv Flash and Modify

- Add Linux desktop packages, Windows ARM64 downloads, per-tool Windows installers and static Linux CLIs, including Raspberry Pi OS.
- Include the matching CLI with each desktop download.
- Add APT, RPM and Arch package repositories.
- Fix Linux desktop startup failures caused by missing runtime libraries.
- Improve rejection of incomplete firmware packages and make drive-disconnection and dump errors clearer.

## [0.10.1]

### freemkv Flash

- Accept Pioneer packages containing the Kernel and Normal files without an extra manifest.
- Check the drive's reported identity after flashing.

## [0.10.0]

### freemkv Flash

- Add backup-first flashing for supported Pioneer Blu-ray drives, including compatible cross-model changes and Kernel downgrades.
- Add Pioneer dump and recovery options.

## [0.9.2]

### freemkv Modify

- Fix an incompatible-medium refusal affecting a triple-layer UHD disc on BU40N 1.00.
- Combine Blu-ray and UHD acceptance under the Unrestricted control. Existing hosts using the former UHD control remain compatible.

## [0.9.1]

### freemkv Modify

- Improve generation of firmware modifications. Existing hardware-validated 0.9.0 images do not require replacement for this change alone.

## [0.9.0]

### freemkv Modify

- Combine the former AKE and Bus controls into one Encryption control. Use freemkv 1.7.5 or newer with this firmware.
- Fix a drive starting with bus encryption disabled when configured to retain OEM behavior.
- Changing Encryption with an empty tray no longer leaves the drive unresponsive to further freemkv commands.

### freemkv Flash

- Stop waiting indefinitely for a drive to become ready and report incomplete verification as a failure.
- Refuse a crossflash when the current firmware cannot be identified.
- Improve rejection of unrelated drives, malformed dump archives and changed drive state before a write.

## [0.8.3]

### freemkv Modify

- Separate reset actions for saved settings, creation-time defaults and OEM behavior.
- Reset to OEM now clears saved freemkv settings. On the next startup, the firmware's creation-time defaults apply.

## [0.8.2]

### freemkv Modify

- Keep Blu-ray and UHD acceptance enabled after restarting the drive, using the defaults selected when the firmware was created.
- Remember deliberately saved OEM-behavior settings instead of treating them as an empty configuration.

## [0.8.1]

### freemkv Modify

- Add support for additional MT1939 firmware variants, with feature availability reported per image.
- Add saved settings and reset controls for speed, region, disc acceptance and encryption-related features.
- Improve matching across supported OEM firmware variants.
- This firmware requires the matching freemkv 1.7.2 host software. Speed and UHD acceptance are unavailable on classic MT1939 firmware.

## [0.7.1]

### freemkv Flash

- Identify additional firmware formats, including Pioneer, Hitachi-LG and Renesas, and distinguish identification support from flashing support.
- Require a closed, empty tray before writing firmware.

## [0.7.0]

### freemkv Flash and Modify

- Refuse corrupted MediaTek images and images for the wrong drive model before writing.
- Report malformed or short OEM images clearly instead of crashing.
- Improve repeated raw-read behavior after a failed or denied read.

## [0.6.2]

### freemkv Modify

- Improve the experimental Raw Read feature so the host can complete the drive's authentication exchange.

## [0.6.1]

### freemkv Modify

- Fix an experimental raw-read command that could leave a BU40N unresponsive until the host was restarted.

## [0.6.0]

### freemkv Modify

- Add experimental firmware creation and identification for LG BU40N. Normal drive commands continue to use the original firmware behavior.

## [0.5.0]

### freemkv Flash

- Introduce firmware identification, dumping and flashing for supported MediaTek optical drives on Windows, macOS and Linux.
- Preview flash plans before execution, save a pre-flash backup and check readback after writing.
- Recognize encrypted MediaTek images and verify firmware integrity.
- Report failed firmware reads rather than silently including bad data in a backup.
