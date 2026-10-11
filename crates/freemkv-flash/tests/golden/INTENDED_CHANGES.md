# Intended behaviour changes since v0.11.2

`tests/golden/v0.11.2/` holds the golden scenarios recorded with the same
harness against the v0.11.2 tag. `golden_parity_with_0_11_2` requires that

* every Pioneer scenario is byte-identical to v0.11.2, and
* every difference in a MediaTek scenario is listed below, under its golden
  file and scenario, line for line (`-` = only in v0.11.2, `+` = only now),
  with one of these reasons:

| id | reason |
|----|--------|
| R1 | MT1939 / generic MediaTek backup rebuilt from the OEM catalog |
| R2 | always-on MT1959/MT1939 chip gate and its extra identity reads |
| R3 | raw-drive-read refusal |
| R4 | known-boot-page requirement |
| R5 | MediaTek `Chipset` info row |
| R6 | round-1 audit fixes (sanitized output, INVALID CMAC report, accurate enter_update message, lazy banner read) |
| R7 | mediatek-optical crate move (CDBs byte-identical; labels and refusal wording come from the shared engine/flashset) |

The baseline set was produced by copying `src/golden_tests.rs` into a
`git worktree` of the v0.11.2 tag and changing only its COMPAT shims
(`mtk_boot_page`, `recover_via`, the `flash_plan` import); blessing it there
writes the files in `v0.11.2/`.

**Removed scenarios.** removed: unreachable path deleted in phase 1 (CLI
main.rs passes force:false; GUI app.rs forces false). These scenarios drove
`FlashRequest.{force, skip_backup, recover}` directly and were dropped from
both the current and the v0.11.2 sets:

* flash_execute.txt: `MTK execute: --skip-backup`, `MTK execute: --force (no
  backup)`, `Pioneer execute: --force, no backup, no installed receiver`,
  `Pioneer execute: --skip-backup`
* mtk_flash_input_refusals.txt: the five `MTK dry run: … (--force)` variants
* pioneer_plan_and_gates.txt: the `recover` and `force` variants of every
  `resolve_flash_plan: installed=…` scenario (the `plain` ones remain)
* pioneer_flash_bundle_failures.txt: `Pioneer flash_bundle: --recover`,
  `Pioneer flash_bundle: --force`

removed in phase 3: `FlashRequest.allow_crossflash` was always false (the CLI
and GUI never set it), so its waiver was unreachable and is deleted. The one
scenario that set it was dropped from both sets:

* flash_dry_run.txt: `Pioneer dry run: bundle with crossflash`

**Added scenarios.** `pioneer_confirm_prompt.txt` (phase 4) covers the CLI
confirmation prompt, TTY and not. Its baseline was recorded at the v0.11.2 tag
with the same harness, driving v0.11.2's `confirm_with` (made `pub(crate)` in
the throwaway worktree, a visibility-only COMPAT change); the current file
drives `engine::flash` and the CLI's prompt core and is byte-identical.

Regenerate the skeleton after an intentional change with
`FREEMKV_BLESS_INTENDED=1 cargo test -p freemkv-flash golden_parity`, then set
the `reason:` of any `UNCLASSIFIED` section by hand.

## backup_capture.txt

### MTK backup: drive-read image
reason: R1
```diff
-OEM-format image: per-drive settings, calibration and revocation lists replaced with factory contents; safe to share and flash back
+this firmware build is not in the OEM catalog (a revision we lack, or a modified image), so the backup is a reconstruction: the boot page and per-drive regions use this chip's factory contents. It carries no personal data and restores the installed firmware code, but it is not a known vendor file
-FIELD    Backup validation = OEM-format image: per-drive settings, calibration and revocation lists replaced with factory contents; safe to share and flash back
-MSG      OEM-format image: per-drive settings, calibration and revocation lists replaced with factory contents; safe to share and flash back
+FIELD    Backup warning = this firmware build is not in the OEM catalog (a revision we lack, or a modified image), so the backup is a reconstruction: the boot page and per-drive regions use this chip's factory contents. It carries no personal data and restores the installed firmware code, but it is not a known vendor file
+MSG      this firmware build is not in the OEM catalog (a revision we lack, or a modified image), so the backup is a reconstruction: the boot page and per-drive regions use this chip's factory contents. It carries no personal data and restores the installed firmware code, but it is not a known vendor file
```

## check_file.txt

### check_file mtk_bad_cmac.bin
reason: R7
```diff
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
```

### check_file mtk_drive_read_backup.bin
reason: R7, R6
```diff
-banner: �����������
+banner: ��������������
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
-MSG      banner: �����������
+MSG      banner: ��������������
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
```

### check_file mtk_flashable.bin
reason: R7
```diff
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
```

### check_file mtk_legacy_0_10_backup.tar
reason: R7
```diff
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
```

### check_file mtk_mt1939_stored.bin
reason: R7, R6
```diff
-banner: �����������
+banner: ������������������
-flash: MediaTek MT1959 — executable (hardware-proven) (image is MT1939 — recognized; only the MT1959 path is proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven) (image is MT1939 — recognized; only the MT1959 path is proven)
-MSG      banner: �����������
+MSG      banner: ������������������
-MSG      flash: MediaTek MT1959 — executable (hardware-proven) (image is MT1939 — recognized; only the MT1959 path is proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven) (image is MT1939 — recognized; only the MT1959 path is proven)
```

### check_file mtk_mt1959_stored.bin
reason: R7, R6
```diff
-banner: �����������
+banner: ��������������
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
-MSG      banner: �����������
+MSG      banner: ��������������
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
```

### check_file mtk_unsigned.bin
reason: R7
```diff
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
```

## flash_dry_run.txt

### MTK drive given a Pioneer bundle
reason: R7
```diff
-result: ERR Pioneer firmware bundles cannot use the MTK flash path
+result: ERR a Pioneer firmware bundle cannot be flashed to this mtk19xx drive
```

### MTK dry run: .bin
reason: R2
```diff
---- scsi transcript (3) ---
+--- scsi transcript (4) ---
+IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
```

### MTK dry run: .bin verbose
reason: R2
```diff
---- scsi transcript (3) ---
+--- scsi transcript (4) ---
+IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
```

### MTK dry run: wrong model refused
reason: R2
```diff
---- scsi transcript (1) ---
+--- scsi transcript (2) ---
+IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
```

## flash_execute.txt

### MTK execute: .bin with pre-flash backup
reason: R2
```diff
---- scsi transcript (784) ---
+--- scsi transcript (785) ---
+IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
```

### MTK execute: Pioneer bundle sent to an MTK drive
reason: R7
```diff
-result: ERR Pioneer firmware bundles cannot use the MTK flash path
+result: ERR a Pioneer firmware bundle cannot be flashed to this mtk19xx drive
```

### MTK execute: no risk acknowledgement
reason: R2
```diff
---- scsi transcript (1) ---
+--- scsi transcript (2) ---
+IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
```

### MTK execute: read-back mismatch
reason: R2
```diff
---- scsi transcript (782) ---
+--- scsi transcript (783) ---
+IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
```

### MTK execute: restore the saved .tar
reason: R2
```diff
---- scsi transcript (784) ---
+--- scsi transcript (785) ---
+IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
```

## info_file.txt

### info_file mtk_bad_cmac.bin
reason: R7
```diff
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
```

### info_file mtk_drive_read_backup.bin
reason: R7, R6
```diff
-banner: �����������
+banner: ��������������
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
-MSG      banner: �����������
+MSG      banner: ��������������
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
```

### info_file mtk_flashable.bin
reason: R7
```diff
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
```

### info_file mtk_legacy_0_10_backup.tar
reason: R7
```diff
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
```

### info_file mtk_mt1939_stored.bin
reason: R7, R6
```diff
-banner: �����������
+banner: ������������������
-flash: MediaTek MT1959 — executable (hardware-proven) (image is MT1939 — recognized; only the MT1959 path is proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven) (image is MT1939 — recognized; only the MT1959 path is proven)
-MSG      banner: �����������
+MSG      banner: ������������������
-MSG      flash: MediaTek MT1959 — executable (hardware-proven) (image is MT1939 — recognized; only the MT1959 path is proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven) (image is MT1939 — recognized; only the MT1959 path is proven)
```

### info_file mtk_mt1959_stored.bin
reason: R7, R6
```diff
-banner: �����������
+banner: ��������������
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
-MSG      banner: �����������
+MSG      banner: ��������������
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
```

### info_file mtk_unsigned.bin
reason: R7
```diff
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
```

## info_mtk.txt

### MTK info: classify-only mock (MockScsiDevice::mtk)
reason: R5, R7
```diff
---- text (33) ---
+--- text (34) ---
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
+chipset: MT1959
---- events (65) ---
+--- events (67) ---
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
+FIELD    Chipset = MT1959
+MSG      chipset: MT1959
---- scsi transcript (21) ---
+--- scsi transcript (23) ---
+IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
+IN   cdb=3c060000300000002000 alloc=32 -> ok 32
```

### MTK info: mock exposing a drive-read firmware image
reason: R5, R7
```diff
---- text (33) ---
+--- text (34) ---
-flash: MediaTek MT1959 — executable (hardware-proven)
+flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
+chipset: MT1959
---- events (65) ---
+--- events (67) ---
-MSG      flash: MediaTek MT1959 — executable (hardware-proven)
+MSG      flash: MediaTek MT19xx (proven on MT1959) — executable (hardware-proven)
+FIELD    Chipset = MT1959
+MSG      chipset: MT1959
---- scsi transcript (21) ---
+--- scsi transcript (22) ---
+IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
```

## mtk_backup_variants.txt

### MTK backup: MT1939 drive read (build not in the catalog)
reason: R1, R4
```diff
-result: ERR unrecognized boot page (sha256 233fadcb958146c4a25a7bde190f956ab7d684fdacb35452f2a39f39ebf81812); no restorable backup can be built for this firmware
---- text (102) ---
+result: OK
+--- text (105) ---
---- events (102) ---
+backup sha256: 9eb55dca2bf12a7ec41a9a0b922aa8a93f18b9eb3bbcf90c5453cc7d5c568d33
+wrote <TMP>/mtk-backup/mt1939.bak (2 MiB).
+this firmware build is not in the OEM catalog (a revision we lack, or a modified image), so the backup is a reconstruction: the boot page and per-drive regions use this chip's factory contents. It carries no personal data and restores the installed firmware code, but it is not a known vendor file
+--- events (107) ---
---- scsi transcript (514) ---
+MSG      backup sha256: 9eb55dca2bf12a7ec41a9a0b922aa8a93f18b9eb3bbcf90c5453cc7d5c568d33
+FIELD    Saved to = <TMP>/mtk-backup/mt1939.bak
+MSG      wrote <TMP>/mtk-backup/mt1939.bak (2 MiB).
+FIELD    Backup warning = this firmware build is not in the OEM catalog (a revision we lack, or a modified image), so the backup is a reconstruction: the boot page and per-drive regions use this chip's factory contents. It carries no personal data and restores the installed firmware code, but it is not a known vendor file
+MSG      this firmware build is not in the OEM catalog (a revision we lack, or a modified image), so the backup is a reconstruction: the boot page and per-drive regions use this chip's factory contents. It carries no personal data and restores the installed firmware code, but it is not a known vendor file
+--- scsi transcript (516) ---
-saved file: <not created>
+IN   cdb=120000006000 alloc=96 -> ok 96
+IN   cdb=3c060000300000002000 alloc=32 -> ok 32
+saved file: 2097152 bytes sha256=9eb55dca2bf12a7ec41a9a0b922aa8a93f18b9eb3bbcf90c5453cc7d5c568d33
```

### MTK backup: MT1959 drive read
reason: R1, R4
```diff
-result: ERR unrecognized boot page (sha256 0bd0297c45ac0fe82554dd385bac39bdbd1b5ee852596f8d5e4630c01ebde361); no restorable backup can be built for this firmware
---- text (102) ---
+result: OK
+--- text (105) ---
---- events (102) ---
+backup sha256: 002f73e3f3423efeb03f7c0c75937d543d04198421ded1db0a1d57474fa8c188
+wrote <TMP>/mtk-backup/mt1959.bak (2 MiB).
+this firmware build is not in the OEM catalog (a revision we lack, or a modified image), so the backup is a reconstruction: the boot page and per-drive regions use this chip's factory contents. It carries no personal data and restores the installed firmware code, but it is not a known vendor file
+--- events (107) ---
---- scsi transcript (514) ---
+MSG      backup sha256: 002f73e3f3423efeb03f7c0c75937d543d04198421ded1db0a1d57474fa8c188
+FIELD    Saved to = <TMP>/mtk-backup/mt1959.bak
+MSG      wrote <TMP>/mtk-backup/mt1959.bak (2 MiB).
+FIELD    Backup warning = this firmware build is not in the OEM catalog (a revision we lack, or a modified image), so the backup is a reconstruction: the boot page and per-drive regions use this chip's factory contents. It carries no personal data and restores the installed firmware code, but it is not a known vendor file
+MSG      this firmware build is not in the OEM catalog (a revision we lack, or a modified image), so the backup is a reconstruction: the boot page and per-drive regions use this chip's factory contents. It carries no personal data and restores the installed firmware code, but it is not a known vendor file
+--- scsi transcript (516) ---
-saved file: <not created>
+IN   cdb=120000006000 alloc=96 -> ok 96
+IN   cdb=3c060000300000002000 alloc=32 -> ok 32
+saved file: 2097152 bytes sha256=002f73e3f3423efeb03f7c0c75937d543d04198421ded1db0a1d57474fa8c188
```

### MTK backup: unknown boot page
reason: R1, R4
```diff
-result: ERR unrecognized boot page (sha256 b40246479629a11e563b32737ccc51e4f0ab10fcf243947fca2f6db424655033); no restorable backup can be built for this firmware
+result: ERR rebuilding the OEM image from the drive read: boot page is neither a stored page nor a drive read's mirror (sha256 b40246479629a11e563b32737ccc51e4f0ab10fcf243947fca2f6db424655033)
```

## mtk_flash_input_refusals.txt

### MTK dry run: MT1939 image on an MT1959 drive
reason: R2
```diff
-result: OK
---- text (13) ---
-== flash plan ==
-device: mock://in-memory
-drive: BU40N
-firmware: 2 MiB (plaintext envelope)
-backup: not captured (dry run)
-upload:    2 MiB streamed verbatim as 128 x 16 KiB chunks, then commit + verify
-
-  ** POINT OF NO RETURN **
-  The drive erases and reprograms its flash the instant the full 2 MiB upload
-  lands. This cannot be undone.
-  preflight ................ transport ready; backup capture is checked only on execute
-
-DRY RUN: no firmware writes or backup capture. Execute may still fail if a complete rollback image cannot be read.
---- events (13) ---
-MSG      == flash plan ==
-MSG      device: mock://in-memory
-MSG      drive: BU40N
-MSG      firmware: 2 MiB (plaintext envelope)
-MSG      backup: not captured (dry run)
-MSG      upload:    2 MiB streamed verbatim as 128 x 16 KiB chunks, then commit + verify
-MSG      
-MSG        ** POINT OF NO RETURN **
-MSG        The drive erases and reprograms its flash the instant the full 2 MiB upload
-MSG        lands. This cannot be undone.
-MSG        preflight ................ transport ready; backup capture is checked only on execute
-MSG      
-MSG      DRY RUN: no firmware writes or backup capture. Execute may still fail if a complete rollback image cannot be read.
---- scsi transcript (3) ---
+result: ERR image is MT1939 firmware but this drive is MT1959 silicon — refusing to flash across chip generations. This gate cannot be overridden.
+--- text (0) ---
+--- events (0) ---
+--- scsi transcript (2) ---
-IN   cdb=3c06001ec000000100000000 alloc=256 -> ok 256
-IN   cdb=000000000000000000000000 alloc=0 -> ok 0
+IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
```

### MTK dry run: disc loaded
reason: R2
```diff
---- scsi transcript (3) ---
+--- scsi transcript (4) ---
+IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
```

### MTK dry run: raw drive read as input
reason: R3
```diff
-result: OK
---- text (13) ---
-== flash plan ==
-device: mock://in-memory
-drive: BU40N
-firmware: 2 MiB (plaintext envelope)
-backup: not captured (dry run)
-upload:    2 MiB streamed verbatim as 128 x 16 KiB chunks, then commit + verify
-
-  ** POINT OF NO RETURN **
-  The drive erases and reprograms its flash the instant the full 2 MiB upload
-  lands. This cannot be undone.
-  preflight ................ transport ready; backup capture is checked only on execute
-
-DRY RUN: no firmware writes or backup capture. Execute may still fail if a complete rollback image cannot be read.
---- events (13) ---
-MSG      == flash plan ==
-MSG      device: mock://in-memory
-MSG      drive: BU40N
-MSG      firmware: 2 MiB (plaintext envelope)
-MSG      backup: not captured (dry run)
-MSG      upload:    2 MiB streamed verbatim as 128 x 16 KiB chunks, then commit + verify
-MSG      
-MSG        ** POINT OF NO RETURN **
-MSG        The drive erases and reprograms its flash the instant the full 2 MiB upload
-MSG        lands. This cannot be undone.
-MSG        preflight ................ transport ready; backup capture is checked only on execute
-MSG      
-MSG      DRY RUN: no firmware writes or backup capture. Execute may still fail if a complete rollback image cannot be read.
---- scsi transcript (3) ---
+result: ERR this is a raw drive read (its boot page is the read-back copy), not a flashable image — refusing to flash. Restore from a freemkv backup .bin, or the vendor's update image. This gate cannot be overridden.
+--- text (0) ---
+--- events (0) ---
+--- scsi transcript (1) ---
-IN   cdb=3c06001ec000000100000000 alloc=256 -> ok 256
-IN   cdb=000000000000000000000000 alloc=0 -> ok 0
```

### MTK dry run: tray open
reason: R2
```diff
---- scsi transcript (3) ---
+--- scsi transcript (4) ---
+IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
```

### MTK dry run: unknown boot page, validly signed
reason: R4, R2
```diff
-result: OK
---- text (13) ---
-== flash plan ==
-device: mock://in-memory
-drive: BU40N
-firmware: 2 MiB (plaintext envelope)
-backup: not captured (dry run)
-upload:    2 MiB streamed verbatim as 128 x 16 KiB chunks, then commit + verify
-
-  ** POINT OF NO RETURN **
-  The drive erases and reprograms its flash the instant the full 2 MiB upload
-  lands. This cannot be undone.
-  preflight ................ transport ready; backup capture is checked only on execute
-
-DRY RUN: no firmware writes or backup capture. Execute may still fail if a complete rollback image cannot be read.
---- events (13) ---
-MSG      == flash plan ==
-MSG      device: mock://in-memory
-MSG      drive: BU40N
-MSG      firmware: 2 MiB (plaintext envelope)
-MSG      backup: not captured (dry run)
-MSG      upload:    2 MiB streamed verbatim as 128 x 16 KiB chunks, then commit + verify
-MSG      
-MSG        ** POINT OF NO RETURN **
-MSG        The drive erases and reprograms its flash the instant the full 2 MiB upload
-MSG        lands. This cannot be undone.
-MSG        preflight ................ transport ready; backup capture is checked only on execute
-MSG      
-MSG      DRY RUN: no firmware writes or backup capture. Execute may still fail if a complete rollback image cannot be read.
---- scsi transcript (3) ---
+result: ERR the image's boot page is not one any known OEM build stores — refusing to flash an image whose boot page may not start the drive
+--- text (0) ---
+--- events (0) ---
+--- scsi transcript (1) ---
-IN   cdb=3c06001ec000000100000000 alloc=256 -> ok 256
-IN   cdb=000000000000000000000000 alloc=0 -> ok 0
```

