# Intended behaviour changes since v0.11.2

`tests/golden/v0.11.2/` holds the golden scenarios recorded with the same
harness against the v0.11.2 tag. `golden_parity_with_0_11_2` requires that
every difference is listed below, under its golden file and scenario, line
for line (`-` = only in v0.11.2, `+` = only now). A Pioneer scenario may
differ only for P1 or P2; a MediaTek scenario only for R1 to R7:

| id | reason |
|----|--------|
| P1 | Pioneer: a package that cannot be read is refused at the plan, before the backup, so no backup file is saved and no `backup:` line is shown |
| P2 | Pioneer: the last tray check runs after the confirmation, right before the first write. A successful flash issues the same device commands. When authorize refuses (or the user declines), there is one fewer tray check. With a disc inserted after the backup, the `backup:` line, the confirmation text and the prompt appear before the refusal |
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

removed with the real-engine Pioneer execute goldens: these drove the
post-backup stages with a hand-made installed backup, which the real engine
cannot produce, because it always captures the backup itself. They were
dropped from both sets:

* pioneer_flash_bundle_failures.txt: `Pioneer flash_bundle: no installed
  backup` (the engine refuses to execute without a saved backup),
  `Pioneer flash_bundle: installed backup is garbage` (the capture builds the
  archive itself) and `Pioneer flash_bundle: installed backup is Normal-only`
  (the capture always reads the Kernel first and stops without it, so it never
  saves a Normal-only backup)

**Moved scenarios.** The Pioneer scenarios that ran the post-backup stages
through a test copy (`authorize`, then `execute` with an ungated grant) now
run the real `engine::flash` end to end on `Ud04Drive`, which replays the
UD04 backup fixture for the pre-flash backup and then takes the OEM update.
Both sets were re-recorded:

* flash_execute.txt `Pioneer flash_bundle: plain update (no kernel patch)` and
  `… update with kernel restoration pass` are now pioneer_execute.txt
  `Pioneer execute: Kernel+Normal update` and `… with kernel restoration pass`
* pioneer_flash_bundle_failures.txt `Pioneer flash_bundle: <case>` is now
  `Pioneer execute: <case>`; the dry-run request is `Pioneer flash: dry-run
  request`

**Added scenarios.** `pioneer_execute.txt` and `pioneer_execute_tty.txt` run
the real Pioneer execute path: Kernel+Normal, restoration pass, Normal-only,
a Normal for another Kernel tag (refused after the backup) and a disc
inserted after the backup, in process with consent given up front (v0.11.2:
its captured-output confirmation), plus the CLI's terminal confirmation in a
child process: stdin not a TTY, and (unix only) a pseudo-terminal answering
`y` or `n`. Both sets were recorded with the same harness; the v0.11.2 child
answers v0.11.2's own `confirm_proceed`. flash_execute.txt gained MediaTek
execute refusals (MT1939 image, raw drive read). The v0.11.2 copy of the
harness needed only COMPAT shims and the pinned `libc` dev-dependency; no
v0.11.2 code changed.

`pioneer_confirm_prompt.txt` (phase 4) covers the CLI
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

### MTK execute: MT1939 image on an MT1959 drive
reason: R2
```diff
-result: OK
---- text (221) ---
-reading drive memory: 0%
-reading drive memory: 1%
-reading drive memory: 2%
-reading drive memory: 3%
-reading drive memory: 4%
-reading drive memory: 5%
-reading drive memory: 6%
-reading drive memory: 7%
-reading drive memory: 8%
-reading drive memory: 9%
-reading drive memory: 10%
-reading drive memory: 11%
-reading drive memory: 12%
-reading drive memory: 13%
-reading drive memory: 14%
-reading drive memory: 15%
-reading drive memory: 16%
-reading drive memory: 17%
-reading drive memory: 18%
-reading drive memory: 19%
-reading drive memory: 20%
-reading drive memory: 21%
-reading drive memory: 22%
-reading drive memory: 23%
-reading drive memory: 24%
-reading drive memory: 25%
-reading drive memory: 26%
-reading drive memory: 27%
-reading drive memory: 28%
-reading drive memory: 29%
-reading drive memory: 30%
-reading drive memory: 31%
-reading drive memory: 32%
-reading drive memory: 33%
-reading drive memory: 34%
-reading drive memory: 35%
-reading drive memory: 36%
-reading drive memory: 37%
-reading drive memory: 38%
-reading drive memory: 39%
-reading drive memory: 40%
-reading drive memory: 41%
-reading drive memory: 42%
-reading drive memory: 43%
-reading drive memory: 44%
-reading drive memory: 45%
-reading drive memory: 46%
-reading drive memory: 47%
-reading drive memory: 48%
-reading drive memory: 49%
-reading drive memory: 50%
-reading drive memory: 51%
-reading drive memory: 52%
-reading drive memory: 53%
-reading drive memory: 54%
-reading drive memory: 55%
-reading drive memory: 56%
-reading drive memory: 57%
-reading drive memory: 58%
-reading drive memory: 59%
-reading drive memory: 60%
-reading drive memory: 61%
-reading drive memory: 62%
-reading drive memory: 63%
-reading drive memory: 64%
-reading drive memory: 65%
-reading drive memory: 66%
-reading drive memory: 67%
-reading drive memory: 68%
-reading drive memory: 69%
-reading drive memory: 70%
-reading drive memory: 71%
-reading drive memory: 72%
-reading drive memory: 73%
-reading drive memory: 74%
-reading drive memory: 75%
-reading drive memory: 76%
-reading drive memory: 77%
-reading drive memory: 78%
-reading drive memory: 79%
-reading drive memory: 80%
-reading drive memory: 81%
-reading drive memory: 82%
-reading drive memory: 83%
-reading drive memory: 84%
-reading drive memory: 85%
-reading drive memory: 86%
-reading drive memory: 87%
-reading drive memory: 88%
-reading drive memory: 89%
-reading drive memory: 90%
-reading drive memory: 91%
-reading drive memory: 92%
-reading drive memory: 93%
-reading drive memory: 94%
-reading drive memory: 95%
-reading drive memory: 96%
-reading drive memory: 97%
-reading drive memory: 98%
-reading drive memory: 99%
-reading drive memory: 100%
-== flash plan ==
-device: mock://in-memory
-drive: BU40N
-firmware: 2 MiB (plaintext envelope)
-backup: saved <TMP>/flash-execute/refused_44.tar (2097152 bytes)
-upload:    2 MiB streamed verbatim as 128 x 16 KiB chunks, then commit + verify
-
-  ** POINT OF NO RETURN **
-  The drive erases and reprograms its flash the instant the full 2 MiB upload
-  lands. This cannot be undone.
-
-EXECUTING flash — do not power off or disconnect the drive...
-flashing firmware: 0%
-flashing firmware: 1%
-flashing firmware: 2%
-flashing firmware: 3%
-flashing firmware: 4%
-flashing firmware: 5%
-flashing firmware: 6%
-flashing firmware: 7%
-flashing firmware: 8%
-flashing firmware: 9%
-flashing firmware: 10%
-flashing firmware: 11%
-flashing firmware: 12%
-flashing firmware: 13%
-flashing firmware: 14%
-flashing firmware: 15%
-flashing firmware: 16%
-flashing firmware: 17%
-flashing firmware: 18%
-flashing firmware: 19%
-flashing firmware: 20%
-flashing firmware: 21%
-flashing firmware: 22%
-flashing firmware: 23%
-flashing firmware: 24%
-flashing firmware: 25%
-flashing firmware: 26%
-flashing firmware: 27%
-flashing firmware: 28%
-flashing firmware: 29%
-flashing firmware: 30%
-flashing firmware: 31%
-flashing firmware: 32%
-flashing firmware: 33%
-flashing firmware: 34%
-flashing firmware: 35%
-flashing firmware: 36%
-flashing firmware: 37%
-flashing firmware: 38%
-flashing firmware: 39%
-flashing firmware: 40%
-flashing firmware: 41%
-flashing firmware: 42%
-flashing firmware: 43%
-flashing firmware: 44%
-flashing firmware: 45%
-flashing firmware: 46%
-flashing firmware: 47%
-flashing firmware: 48%
-flashing firmware: 49%
-flashing firmware: 50%
-flashing firmware: 51%
-flashing firmware: 52%
-flashing firmware: 53%
-flashing firmware: 54%
-flashing firmware: 55%
-flashing firmware: 56%
-flashing firmware: 57%
-flashing firmware: 58%
-flashing firmware: 59%
-flashing firmware: 60%
-flashing firmware: 61%
-flashing firmware: 62%
-flashing firmware: 63%
-flashing firmware: 64%
-flashing firmware: 65%
-flashing firmware: 66%
-flashing firmware: 67%
-flashing firmware: 68%
-flashing firmware: 69%
-flashing firmware: 70%
-flashing firmware: 71%
-flashing firmware: 72%
-flashing firmware: 73%
-flashing firmware: 74%
-flashing firmware: 75%
-flashing firmware: 76%
-flashing firmware: 77%
-flashing firmware: 78%
-flashing firmware: 79%
-flashing firmware: 80%
-flashing firmware: 81%
-flashing firmware: 82%
-flashing firmware: 83%
-flashing firmware: 84%
-flashing firmware: 85%
-flashing firmware: 86%
-flashing firmware: 87%
-flashing firmware: 88%
-flashing firmware: 89%
-flashing firmware: 90%
-flashing firmware: 91%
-flashing firmware: 92%
-flashing firmware: 93%
-flashing firmware: 94%
-flashing firmware: 95%
-flashing firmware: 96%
-flashing firmware: 97%
-flashing firmware: 98%
-flashing firmware: 99%
-flashing firmware: 100%
-warning: could not parse the post-flash REQUEST SENSE response (16 bytes); relying on read-back verify
-upload complete (2 MiB); waiting for the drive to finish programming...
-warning: post-settle REQUEST SENSE returned an unparseable 16-byte reply; relying on read-back verify.
-verifying...
-  flash complete ........... 60 KiB of integrity-protected regions verified
-  Integrity is enforced on-device: the drive recomputes CMAC at boot and rejects a bad image. The firmware identity below is the real result.
-firmware now: unrecognized  [23bb815101f96a052dc1d38e99aec791beef80a4586bbec90109090045a871aa]
---- events (221) ---
-PROGRESS reading drive memory 4096/2097152
-PROGRESS reading drive memory 24576/2097152
-PROGRESS reading drive memory 45056/2097152
-PROGRESS reading drive memory 65536/2097152
-PROGRESS reading drive memory 86016/2097152
-PROGRESS reading drive memory 106496/2097152
-PROGRESS reading drive memory 126976/2097152
-PROGRESS reading drive memory 147456/2097152
-PROGRESS reading drive memory 167936/2097152
-PROGRESS reading drive memory 192512/2097152
-PROGRESS reading drive memory 212992/2097152
-PROGRESS reading drive memory 233472/2097152
-PROGRESS reading drive memory 253952/2097152
-PROGRESS reading drive memory 274432/2097152
-PROGRESS reading drive memory 294912/2097152
-PROGRESS reading drive memory 315392/2097152
-PROGRESS reading drive memory 335872/2097152
-PROGRESS reading drive memory 360448/2097152
-PROGRESS reading drive memory 380928/2097152
-PROGRESS reading drive memory 401408/2097152
-PROGRESS reading drive memory 421888/2097152
-PROGRESS reading drive memory 442368/2097152
-PROGRESS reading drive memory 462848/2097152
-PROGRESS reading drive memory 483328/2097152
-PROGRESS reading drive memory 503808/2097152
-PROGRESS reading drive memory 524288/2097152
-PROGRESS reading drive memory 548864/2097152
-PROGRESS reading drive memory 569344/2097152
-PROGRESS reading drive memory 589824/2097152
-PROGRESS reading drive memory 610304/2097152
-PROGRESS reading drive memory 630784/2097152
-PROGRESS reading drive memory 651264/2097152
-PROGRESS reading drive memory 671744/2097152
-PROGRESS reading drive memory 692224/2097152
-PROGRESS reading drive memory 716800/2097152
-PROGRESS reading drive memory 737280/2097152
-PROGRESS reading drive memory 757760/2097152
-PROGRESS reading drive memory 778240/2097152
-PROGRESS reading drive memory 798720/2097152
-PROGRESS reading drive memory 819200/2097152
-PROGRESS reading drive memory 839680/2097152
-PROGRESS reading drive memory 860160/2097152
-PROGRESS reading drive memory 884736/2097152
-PROGRESS reading drive memory 905216/2097152
-PROGRESS reading drive memory 925696/2097152
-PROGRESS reading drive memory 946176/2097152
-PROGRESS reading drive memory 966656/2097152
-PROGRESS reading drive memory 987136/2097152
-PROGRESS reading drive memory 1007616/2097152
-PROGRESS reading drive memory 1028096/2097152
-PROGRESS reading drive memory 1048576/2097152
-PROGRESS reading drive memory 1073152/2097152
-PROGRESS reading drive memory 1093632/2097152
-PROGRESS reading drive memory 1114112/2097152
-PROGRESS reading drive memory 1134592/2097152
-PROGRESS reading drive memory 1155072/2097152
-PROGRESS reading drive memory 1175552/2097152
-PROGRESS reading drive memory 1196032/2097152
-PROGRESS reading drive memory 1216512/2097152
-PROGRESS reading drive memory 1241088/2097152
-PROGRESS reading drive memory 1261568/2097152
-PROGRESS reading drive memory 1282048/2097152
-PROGRESS reading drive memory 1302528/2097152
-PROGRESS reading drive memory 1323008/2097152
-PROGRESS reading drive memory 1343488/2097152
-PROGRESS reading drive memory 1363968/2097152
-PROGRESS reading drive memory 1384448/2097152
-PROGRESS reading drive memory 1409024/2097152
-PROGRESS reading drive memory 1429504/2097152
-PROGRESS reading drive memory 1449984/2097152
-PROGRESS reading drive memory 1470464/2097152
-PROGRESS reading drive memory 1490944/2097152
-PROGRESS reading drive memory 1511424/2097152
-PROGRESS reading drive memory 1531904/2097152
-PROGRESS reading drive memory 1552384/2097152
-PROGRESS reading drive memory 1572864/2097152
-PROGRESS reading drive memory 1597440/2097152
-PROGRESS reading drive memory 1617920/2097152
-PROGRESS reading drive memory 1638400/2097152
-PROGRESS reading drive memory 1658880/2097152
-PROGRESS reading drive memory 1679360/2097152
-PROGRESS reading drive memory 1699840/2097152
-PROGRESS reading drive memory 1720320/2097152
-PROGRESS reading drive memory 1740800/2097152
-PROGRESS reading drive memory 1765376/2097152
-PROGRESS reading drive memory 1785856/2097152
-PROGRESS reading drive memory 1806336/2097152
-PROGRESS reading drive memory 1826816/2097152
-PROGRESS reading drive memory 1847296/2097152
-PROGRESS reading drive memory 1867776/2097152
-PROGRESS reading drive memory 1888256/2097152
-PROGRESS reading drive memory 1908736/2097152
-PROGRESS reading drive memory 1933312/2097152
-PROGRESS reading drive memory 1953792/2097152
-PROGRESS reading drive memory 1974272/2097152
-PROGRESS reading drive memory 1994752/2097152
-PROGRESS reading drive memory 2015232/2097152
-PROGRESS reading drive memory 2035712/2097152
-PROGRESS reading drive memory 2056192/2097152
-PROGRESS reading drive memory 2076672/2097152
-PROGRESS reading drive memory 2097152/2097152
-MSG      == flash plan ==
-MSG      device: mock://in-memory
-MSG      drive: BU40N
-MSG      firmware: 2 MiB (plaintext envelope)
-MSG      backup: saved <TMP>/flash-execute/refused_44.tar (2097152 bytes)
-MSG      upload:    2 MiB streamed verbatim as 128 x 16 KiB chunks, then commit + verify
-MSG      
-MSG        ** POINT OF NO RETURN **
-MSG        The drive erases and reprograms its flash the instant the full 2 MiB upload
-MSG        lands. This cannot be undone.
-MSG      
-MSG      EXECUTING flash — do not power off or disconnect the drive...
-PROGRESS flashing firmware 16384/2097152
-PROGRESS flashing firmware 32768/2097152
-PROGRESS flashing firmware 49152/2097152
-PROGRESS flashing firmware 65536/2097152
-PROGRESS flashing firmware 98304/2097152
-PROGRESS flashing firmware 114688/2097152
-PROGRESS flashing firmware 131072/2097152
-PROGRESS flashing firmware 147456/2097152
-PROGRESS flashing firmware 180224/2097152
-PROGRESS flashing firmware 196608/2097152
-PROGRESS flashing firmware 212992/2097152
-PROGRESS flashing firmware 245760/2097152
-PROGRESS flashing firmware 262144/2097152
-PROGRESS flashing firmware 278528/2097152
-PROGRESS flashing firmware 294912/2097152
-PROGRESS flashing firmware 327680/2097152
-PROGRESS flashing firmware 344064/2097152
-PROGRESS flashing firmware 360448/2097152
-PROGRESS flashing firmware 393216/2097152
-PROGRESS flashing firmware 409600/2097152
-PROGRESS flashing firmware 425984/2097152
-PROGRESS flashing firmware 442368/2097152
-PROGRESS flashing firmware 475136/2097152
-PROGRESS flashing firmware 491520/2097152
-PROGRESS flashing firmware 507904/2097152
-PROGRESS flashing firmware 524288/2097152
-PROGRESS flashing firmware 557056/2097152
-PROGRESS flashing firmware 573440/2097152
-PROGRESS flashing firmware 589824/2097152
-PROGRESS flashing firmware 622592/2097152
-PROGRESS flashing firmware 638976/2097152
-PROGRESS flashing firmware 655360/2097152
-PROGRESS flashing firmware 671744/2097152
-PROGRESS flashing firmware 704512/2097152
-PROGRESS flashing firmware 720896/2097152
-PROGRESS flashing firmware 737280/2097152
-PROGRESS flashing firmware 770048/2097152
-PROGRESS flashing firmware 786432/2097152
-PROGRESS flashing firmware 802816/2097152
-PROGRESS flashing firmware 819200/2097152
-PROGRESS flashing firmware 851968/2097152
-PROGRESS flashing firmware 868352/2097152
-PROGRESS flashing firmware 884736/2097152
-PROGRESS flashing firmware 917504/2097152
-PROGRESS flashing firmware 933888/2097152
-PROGRESS flashing firmware 950272/2097152
-PROGRESS flashing firmware 966656/2097152
-PROGRESS flashing firmware 999424/2097152
-PROGRESS flashing firmware 1015808/2097152
-PROGRESS flashing firmware 1032192/2097152
-PROGRESS flashing firmware 1048576/2097152
-PROGRESS flashing firmware 1081344/2097152
-PROGRESS flashing firmware 1097728/2097152
-PROGRESS flashing firmware 1114112/2097152
-PROGRESS flashing firmware 1146880/2097152
-PROGRESS flashing firmware 1163264/2097152
-PROGRESS flashing firmware 1179648/2097152
-PROGRESS flashing firmware 1196032/2097152
-PROGRESS flashing firmware 1228800/2097152
-PROGRESS flashing firmware 1245184/2097152
-PROGRESS flashing firmware 1261568/2097152
-PROGRESS flashing firmware 1294336/2097152
-PROGRESS flashing firmware 1310720/2097152
-PROGRESS flashing firmware 1327104/2097152
-PROGRESS flashing firmware 1343488/2097152
-PROGRESS flashing firmware 1376256/2097152
-PROGRESS flashing firmware 1392640/2097152
-PROGRESS flashing firmware 1409024/2097152
-PROGRESS flashing firmware 1441792/2097152
-PROGRESS flashing firmware 1458176/2097152
-PROGRESS flashing firmware 1474560/2097152
-PROGRESS flashing firmware 1490944/2097152
-PROGRESS flashing firmware 1523712/2097152
-PROGRESS flashing firmware 1540096/2097152
-PROGRESS flashing firmware 1556480/2097152
-PROGRESS flashing firmware 1572864/2097152
-PROGRESS flashing firmware 1605632/2097152
-PROGRESS flashing firmware 1622016/2097152
-PROGRESS flashing firmware 1638400/2097152
-PROGRESS flashing firmware 1671168/2097152
-PROGRESS flashing firmware 1687552/2097152
-PROGRESS flashing firmware 1703936/2097152
-PROGRESS flashing firmware 1720320/2097152
-PROGRESS flashing firmware 1753088/2097152
-PROGRESS flashing firmware 1769472/2097152
-PROGRESS flashing firmware 1785856/2097152
-PROGRESS flashing firmware 1818624/2097152
-PROGRESS flashing firmware 1835008/2097152
-PROGRESS flashing firmware 1851392/2097152
-PROGRESS flashing firmware 1867776/2097152
-PROGRESS flashing firmware 1900544/2097152
-PROGRESS flashing firmware 1916928/2097152
-PROGRESS flashing firmware 1933312/2097152
-PROGRESS flashing firmware 1966080/2097152
-PROGRESS flashing firmware 1982464/2097152
-PROGRESS flashing firmware 1998848/2097152
-PROGRESS flashing firmware 2015232/2097152
-PROGRESS flashing firmware 2048000/2097152
-PROGRESS flashing firmware 2064384/2097152
-PROGRESS flashing firmware 2080768/2097152
-PROGRESS flashing firmware 2097152/2097152
-MSG      warning: could not parse the post-flash REQUEST SENSE response (16 bytes); relying on read-back verify
-MSG      upload complete (2 MiB); waiting for the drive to finish programming...
-MSG      warning: post-settle REQUEST SENSE returned an unparseable 16-byte reply; relying on read-back verify.
-MSG      verifying...
-MSG        flash complete ........... 60 KiB of integrity-protected regions verified
-MSG        Integrity is enforced on-device: the drive recomputes CMAC at boot and rejects a bad image. The firmware identity below is the real result.
-MSG      firmware now: unrecognized  [23bb815101f96a052dc1d38e99aec791beef80a4586bbec90109090045a871aa]
---- scsi transcript (784) ---
-MEDIUM -> ClosedEmpty
-IN   cdb=3c060000000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000aa00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ab00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ac00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ad00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ae00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000af00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ba00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000bb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000bc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000bd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000be00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000bf00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ca00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000cb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000cc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000cd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ce00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000cf00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000da00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000db00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000dc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000dd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000de00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000df00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ea00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000eb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ec00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ed00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ee00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ef00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000fa00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000fb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000fc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000fd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000fe00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ff00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001aa00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ab00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ac00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ad00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ae00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001af00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ba00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001bb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001bc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001bd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001be00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001bf00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ca00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001cb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001cc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001cd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ce00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001cf00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001da00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001db00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001dc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001dd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001de00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001df00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ea00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001eb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ec00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ed00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ee00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ef00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001fa00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001fb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001fc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001fd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001fe00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ff00000100000 alloc=4096 -> ok 4096
-IN   cdb=120000006000 alloc=96 -> ok 96
-IN   cdb=3c060000300000002000 alloc=32 -> ok 32
-IN   cdb=120000006000 alloc=96 -> ok 96
-IN   cdb=3c060000300000002000 alloc=32 -> ok 32
+result: ERR image is MT1939 firmware but this drive is MT1959 silicon — refusing to flash across chip generations. This gate cannot be overridden.
+--- text (0) ---
+--- events (0) ---
+--- scsi transcript (2) ---
-IN   cdb=3c06001ec000000100000000 alloc=256 -> ok 256
-IN   cdb=000000000000000000000000 alloc=0 -> ok 0
-OUTS cdb=3b01000000000000000b0000 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-OUTS cdb=3b0600000000004000000000 len=16384 sha256=e28691dac174f1b5b82b862826925ad849e81ef799b0e712f2882986f2253cb7 -> ok
-OUTS cdb=3b0600004000004000000000 len=16384 sha256=e720708b81e40bf2bc273cbf9a593fa8e07050b600b71e89ef096fff9dfd27e8 -> ok
-OUTS cdb=3b0600008000004000000000 len=16384 sha256=5f68c6f9da037e85ca27b5b0f3f7d790da2cf8b43d905cc963b329a91751ca5d -> ok
-OUTS cdb=3b060000c000004000000000 len=16384 sha256=080ce19ee0ed294c5288f49426902263e96366a84d414412ad1eeb3dbc5cb5f5 -> ok
-OUTS cdb=3b0600010000004000000000 len=16384 sha256=0a73933b9c89ab464c4b805e9abe1d1a750669a6c97a03de25e311b83198f00c -> ok
-OUTS cdb=3b0600014000004000000000 len=16384 sha256=f15ee21e81e678cfe8e5b6784ecc43f0eaa5b2f5981bb77b0d853718c414d07d -> ok
-OUTS cdb=3b0600018000004000000000 len=16384 sha256=095f37811f34315fe0e57b6d042b1fb7af8f7ecc85a468d78e5732492becb8af -> ok
-OUTS cdb=3b060001c000004000000000 len=16384 sha256=d3caa063844f2ede22d6a7202859f1e8d00c76a1722c2defac0d886463befb89 -> ok
-OUTS cdb=3b0600020000004000000000 len=16384 sha256=94e09640e0a46706d3270fae71e3f18f8c43b9e3d519cc9270a83b4fb3c88aef -> ok
-OUTS cdb=3b0600024000004000000000 len=16384 sha256=0690a5b4ac8fd5e3730df08890efabc4d920eab482cd47defed991a5489a71af -> ok
-OUTS cdb=3b0600028000004000000000 len=16384 sha256=7c378ae5769dea4d7f4e29f18e8717f10c26e8e416e8da1df860c79a0d630dda -> ok
-OUTS cdb=3b060002c000004000000000 len=16384 sha256=cb03a33c6600367b988298792946c72309c2497667b430b6acc152759a808ed4 -> ok
-OUTS cdb=3b0600030000004000000000 len=16384 sha256=3259933e1118189cc5495fca40ebbdd9944f998db8c835cf98e8327d826fd47d -> ok
-OUTS cdb=3b0600034000004000000000 len=16384 sha256=dac75e8748dfe828ffae864a2a4dc4c8c64fdc5e7a432a5852e4c8a9ba2a01b2 -> ok
-OUTS cdb=3b0600038000004000000000 len=16384 sha256=87239ec7874daa70fce81fb60065697f3b08e020e0db841a1c3482c6fc0509db -> ok
-OUTS cdb=3b060003c000004000000000 len=16384 sha256=7e439ccbd202207731a447cb5d399bba513cb0aa41cb4fc4f62c5a387f62fcf0 -> ok
-OUTS cdb=3b0600040000004000000000 len=16384 sha256=cb4d76c10027e9a93d5a1eb2b7b4f2bdbd2127fef966d9c801f45419f6d68354 -> ok
-OUTS cdb=3b0600044000004000000000 len=16384 sha256=33a2fc9dcef97f06d18f3312a638caec0b6b4159ceb778fc012354ec48856697 -> ok
-OUTS cdb=3b0600048000004000000000 len=16384 sha256=b92893a270a49768d5408808152497cc7e0bec8e963feb9afe1e4afbccf830d4 -> ok
-OUTS cdb=3b060004c000004000000000 len=16384 sha256=1cb9443027db701c585e5a355513f4e5a60f5d34fd9d7e58bf62d90e22e1eb8e -> ok
-OUTS cdb=3b0600050000004000000000 len=16384 sha256=9e418613f72f1cf26ce556fe99735e345132db5227a100d00e49bc7ed71131a1 -> ok
-OUTS cdb=3b0600054000004000000000 len=16384 sha256=f6512e82635974095f07dea2df4c66fa88e590f86c4ed861a24ab01de3a02187 -> ok
-OUTS cdb=3b0600058000004000000000 len=16384 sha256=6b69bf723bf0cd9f54773ef8c0932a1a46ba21fde7251812650291ac467fe46c -> ok
-OUTS cdb=3b060005c000004000000000 len=16384 sha256=f0ff4a64cbf90ad5f2e4f4e243ea46e5333ab26ebf1888fdeed19f29522f1f18 -> ok
-OUTS cdb=3b0600060000004000000000 len=16384 sha256=8fc14867ea42217024871f0f06e747708346929723da7a7547b0290fae5cddd7 -> ok
-OUTS cdb=3b0600064000004000000000 len=16384 sha256=2c01b0f1ed09608d7fd9384e0d8d5bfde05864d50216753411c88e154ee4cb7f -> ok
-OUTS cdb=3b0600068000004000000000 len=16384 sha256=bee6a2ab268c601c9ed80d6156985c897d2689d6f0aa7879e66ee7ba3a55d302 -> ok
-OUTS cdb=3b060006c000004000000000 len=16384 sha256=609c0438cee13ca9159830268bad51e1e9f9236eb9b192440ff551d0ff958ab6 -> ok
-OUTS cdb=3b0600070000004000000000 len=16384 sha256=ecb48a2c92d5214aa01d928db20e2c28fedadfea3d2df5700e2b895ea2bec42c -> ok
-OUTS cdb=3b0600074000004000000000 len=16384 sha256=be47ce9cb6c6a55468a3591aafcce7f889280af5d44dd55f470f3e4fd51d13b4 -> ok
-OUTS cdb=3b0600078000004000000000 len=16384 sha256=6db0b02515c6e901511426198ce8f94406b01e69a5cf3f9d1328f525135e2e0a -> ok
-OUTS cdb=3b060007c000004000000000 len=16384 sha256=158b5818a6ae049107b9ee1736bc0fcc8d318af59c20525eb5bd010fcd4bd127 -> ok
-OUTS cdb=3b0600080000004000000000 len=16384 sha256=7acc6f262c0c05e6d49c5b67ef1555b19cd2726e09b5b16b3700f6ecf8bcf177 -> ok
-OUTS cdb=3b0600084000004000000000 len=16384 sha256=485fae2016758d3ff932f7c0e40d9917aab8d228a59fc011fb8dc391365d060b -> ok
-OUTS cdb=3b0600088000004000000000 len=16384 sha256=f0145e1d11e9c9ea56bd0397c1e8f50be48e93f793dee8a867de1faed8f120b0 -> ok
-OUTS cdb=3b060008c000004000000000 len=16384 sha256=3a359a6bf129de0dc0300a39c32b7d8f3938cf6c4191dd1cdb30fd9ee10d6e5d -> ok
-OUTS cdb=3b0600090000004000000000 len=16384 sha256=4270023173a8053d3de2f017b0ff8daf20dfd31ea2d1a16507d7a48ca9a0605a -> ok
-OUTS cdb=3b0600094000004000000000 len=16384 sha256=73e344d671b34c0c713411629cfc33e6dce56354624907299c80715c021dc4b9 -> ok
-OUTS cdb=3b0600098000004000000000 len=16384 sha256=32b18839bce5454576d1d5cfa4e619aee37704dc0c55fe602e3fdd805decb2d0 -> ok
-OUTS cdb=3b060009c000004000000000 len=16384 sha256=1d03ed5ecec080eb58aa01fcc6dcb2930cb28b9982fbd10e1a102e078753b856 -> ok
-OUTS cdb=3b06000a0000004000000000 len=16384 sha256=7991f182db4dd3c493829bb98af2471f0fc5ef6b81b31402d76b316ba7fb79e2 -> ok
-OUTS cdb=3b06000a4000004000000000 len=16384 sha256=b745869c66c78e322f603cbc821519a61faf96ec242b09680c6e6a5400267fc2 -> ok
-OUTS cdb=3b06000a8000004000000000 len=16384 sha256=d4dab7bf9d391d6f8a5f4c91ea956207acc5e45ea076d111be14c0cb0b828943 -> ok
-OUTS cdb=3b06000ac000004000000000 len=16384 sha256=cb7d7fd76204b2ebce1d5004171f125c7bd581bfa7adb55bd8417da4a79eec01 -> ok
-OUTS cdb=3b06000b0000004000000000 len=16384 sha256=a4e6ae369e9493e932ecc9dfa030dbac8683d91f6db96d0b11ffd7f2f32e5000 -> ok
-OUTS cdb=3b06000b4000004000000000 len=16384 sha256=5e4d145ea6bbcaf5d05cd822ccd23f18f99277cc11703b92310a5808a074d297 -> ok
-OUTS cdb=3b06000b8000004000000000 len=16384 sha256=e884fec69679709c3862c0226c6208cb38b852d9c57c5103b1c78bced0f615af -> ok
-OUTS cdb=3b06000bc000004000000000 len=16384 sha256=532e9a3d1991b98c7ab64a1f988a55595230b632ce47ec20963bd1b6f00f346b -> ok
-OUTS cdb=3b06000c0000004000000000 len=16384 sha256=4ae3e07219d40826ff9228dcb322c4ef90363d038550f7270e008a2ed138522c -> ok
-OUTS cdb=3b06000c4000004000000000 len=16384 sha256=ad0865a82b1c4110229ddcb66e9da258182393eb85d5ad5f0dd2cb4f57c3a903 -> ok
-OUTS cdb=3b06000c8000004000000000 len=16384 sha256=a1c890278a9c0be38f9721289437cede743e5a62b3c02963521ed147468c5ccc -> ok
-OUTS cdb=3b06000cc000004000000000 len=16384 sha256=0478fa543cbee0b06880c7b97358b6767ac42a58afd22d7d345085076332bb97 -> ok
-OUTS cdb=3b06000d0000004000000000 len=16384 sha256=1fa6c7e411e4553b24b0bb04a42c8bc7d064b471cdc43664ba7beb87f0e9273f -> ok
-OUTS cdb=3b06000d4000004000000000 len=16384 sha256=aaf35a2309dbf2ad9a0d782ab90947ced394740601999f1fc1436a1857b36812 -> ok
-OUTS cdb=3b06000d8000004000000000 len=16384 sha256=a2849a643b4d1485eeffee70f0afb20cbfdafb09f2685edc363feec4fc59d218 -> ok
-OUTS cdb=3b06000dc000004000000000 len=16384 sha256=b33bf0d4cdcc332203a65132ec2f295f94527949a1c51ae352cf71f877f27375 -> ok
-OUTS cdb=3b06000e0000004000000000 len=16384 sha256=27b079ab901405164052d4d130239c8833b5689f34c0faf9926e720622e9377f -> ok
-OUTS cdb=3b06000e4000004000000000 len=16384 sha256=5b03db3c8b66594d0fd1a840ba89fda9ead4ed3ef7a774a8a8d6e51fa6fe126a -> ok
-OUTS cdb=3b06000e8000004000000000 len=16384 sha256=c0173ed2edfcf169b166c044527792527d018ed49ec635b9edfcefe0efcf8f9a -> ok
-OUTS cdb=3b06000ec000004000000000 len=16384 sha256=95186e7e174007c434849f7d81730348cdd036be0636c02c67fc4d4715bb7859 -> ok
-OUTS cdb=3b06000f0000004000000000 len=16384 sha256=2eff5a364a1a80d7bf4c43f684109a637fa91d51f11bc02abe4c2b53d195560d -> ok
-OUTS cdb=3b06000f4000004000000000 len=16384 sha256=24b845027e96d2fc8762a1d1eab4d3a2b2b5f5babf762a54294b9d4b92aac66d -> ok
-OUTS cdb=3b06000f8000004000000000 len=16384 sha256=c49472228fd90803fffe6d7e0c16f5a805447d7f3edfe80871562eb91451490b -> ok
-OUTS cdb=3b06000fc000004000000000 len=16384 sha256=9d3ed927374cabed71d341c79fd3840da027533d19312493fb757656cb4b4373 -> ok
-OUTS cdb=3b0600100000004000000000 len=16384 sha256=20fc3f3bf93f6f8890154e05cb8134c7c0919ae58bd7d81f2b572820ff21cc58 -> ok
-OUTS cdb=3b0600104000004000000000 len=16384 sha256=029c549c5707d66a8c9339937d61711959c6db8767375e62d29ee5c4a48dbdb6 -> ok
-OUTS cdb=3b0600108000004000000000 len=16384 sha256=f7ebd45b0948d1e02213bf2acd1b754af41d279dc00c978dbd67982050d2190b -> ok
-OUTS cdb=3b060010c000004000000000 len=16384 sha256=e7a184e6e90a58c76112c52e5027f0f43b40b078ced62fc62752ead1936ee2ad -> ok
-OUTS cdb=3b0600110000004000000000 len=16384 sha256=afddb69baba0cfe5e4abc6e8a1377cd976cf78922361c6fde815892fa8802882 -> ok
-OUTS cdb=3b0600114000004000000000 len=16384 sha256=55cdd4e5f323be2983795df6963bd0f27e4225608a2df723b27a7eeb457b948b -> ok
-OUTS cdb=3b0600118000004000000000 len=16384 sha256=64eafd53000bfa32de277eb0e9aaaaed4748af7fe34deeb90abcce9dc9cbb7f2 -> ok
-OUTS cdb=3b060011c000004000000000 len=16384 sha256=ddd3e3f02938b51a3c6cc036b1f1fd801c2a8026fa455ecba5ea7b4f581c7545 -> ok
-OUTS cdb=3b0600120000004000000000 len=16384 sha256=783700293aa48fb2bfe085b411129179edbe77d37f5a17855d351e3f9f299d18 -> ok
-OUTS cdb=3b0600124000004000000000 len=16384 sha256=5a4b9b2978e03fb758b65cf06e551fec3d6de846d417fbb541b33019a0ca5d80 -> ok
-OUTS cdb=3b0600128000004000000000 len=16384 sha256=c53e704410588b384ee4614671f4f7a03fd6da619d69ca858d489f359023b409 -> ok
-OUTS cdb=3b060012c000004000000000 len=16384 sha256=de0cf267e239d09d2c32daf2e7134430d12cd7ce2602eb4ae77d77c165a556a5 -> ok
-OUTS cdb=3b0600130000004000000000 len=16384 sha256=e92a8df3f0dc66f759e416e5716d28dd321d75f3b4642f3b44e3cc7780a55fba -> ok
-OUTS cdb=3b0600134000004000000000 len=16384 sha256=7c233790cbc163fd9e4770a40cd53646c783dd880786d647c64326726f83b657 -> ok
-OUTS cdb=3b0600138000004000000000 len=16384 sha256=52955c3a17d0aff9046d9ba2bc72ed242c8f023bd19f1984d7ec1360597c5a87 -> ok
-OUTS cdb=3b060013c000004000000000 len=16384 sha256=95b8f141482bc7c0fd339057aec0a8af02522d34dc47609e0224f9b579f8c08b -> ok
-OUTS cdb=3b0600140000004000000000 len=16384 sha256=6b0a1b9f12ca5e9b2fec679fc3004b9b2f495a56cb60ed3907e84c79c02c492d -> ok
-OUTS cdb=3b0600144000004000000000 len=16384 sha256=42562753522cd4988909dd1e5ee0b56e4c5e314b6803375869475c155bf8419f -> ok
-OUTS cdb=3b0600148000004000000000 len=16384 sha256=86201eec1646bd16fe3b32ede3263b993d3c80301520928898b954610a92856b -> ok
-OUTS cdb=3b060014c000004000000000 len=16384 sha256=d484412443264e0b58ed89d9a8bb20088adf4fc1c96b02d64dd3e23e8dec665e -> ok
-OUTS cdb=3b0600150000004000000000 len=16384 sha256=6765325c656b3b59f19d1bb06a1dc7b7349e29144a70c02e12759225eb2615ae -> ok
-OUTS cdb=3b0600154000004000000000 len=16384 sha256=6742891b2341162648d91b7e02987de6a7d7d00ea20c6ac0762e9f784a9632e8 -> ok
-OUTS cdb=3b0600158000004000000000 len=16384 sha256=bc297804ebc261153f9f3a15b732efffd0aaa9a962fed61f117648d48185b807 -> ok
-OUTS cdb=3b060015c000004000000000 len=16384 sha256=610e3f8421990bb93e32ea3fd6466917088d0cc9419b352cc9b1be3daba7ef3a -> ok
-OUTS cdb=3b0600160000004000000000 len=16384 sha256=1717eb869b97fed6a9aa882d8040085045647cb545dd2535552e29e5f2cda0ce -> ok
-OUTS cdb=3b0600164000004000000000 len=16384 sha256=219be172635dde3263cc305ca67b9d61756a9343b72fd76beadbf8b610b3695c -> ok
-OUTS cdb=3b0600168000004000000000 len=16384 sha256=28c710a0bbde3a9908046bf265e35e18fac40e490071f9ae57b5d214a1fee4d6 -> ok
-OUTS cdb=3b060016c000004000000000 len=16384 sha256=8b69e9a0ecdfcb48a30abf92079864bac8f5bb6b710ea9ca255876177a97f53f -> ok
-OUTS cdb=3b0600170000004000000000 len=16384 sha256=da49ab8e54a9789d1e540fc629b257d16969e71385230969a7e142162e1dd390 -> ok
-OUTS cdb=3b0600174000004000000000 len=16384 sha256=b08c5a92d6ae5e52345377d06627e23f81b7f3d54fec42bd08c664c6202effaa -> ok
-OUTS cdb=3b0600178000004000000000 len=16384 sha256=5085d20e964c387df925ce74e1b50ce0f968fff058338c00877ed8a550c2038a -> ok
-OUTS cdb=3b060017c000004000000000 len=16384 sha256=ac68173edac0977d997fcf03656b683c939b66e430a4f93308483ef970393402 -> ok
-OUTS cdb=3b0600180000004000000000 len=16384 sha256=b758cc1adfef79571ffd37bfd85cb597ef1f9a805804deaeb576a383c59834a1 -> ok
-OUTS cdb=3b0600184000004000000000 len=16384 sha256=cf7b69c13c7108d6769b4f17fd61ecd186a43549e07715c9be7542a082f79779 -> ok
-OUTS cdb=3b0600188000004000000000 len=16384 sha256=ea4eacb4f35343adacd0b9559447597277751fe8fd78bb50f250d426bff11c5d -> ok
-OUTS cdb=3b060018c000004000000000 len=16384 sha256=aab4332736cf0d3c9a172dadf4701372a6e8484c41d4cdda23154466913c76cd -> ok
-OUTS cdb=3b0600190000004000000000 len=16384 sha256=dec9ad020e950205872dee374970d8adead132ae8eb09549e80cd5ffcaa32693 -> ok
-OUTS cdb=3b0600194000004000000000 len=16384 sha256=9409d02bca2e6f0b9671e56f498c21e918fce8fd6c5f39471f881cfc010ee7f9 -> ok
-OUTS cdb=3b0600198000004000000000 len=16384 sha256=892a190a2b26b9a4749dc52d2044a656dfb13e961371a03ba0a6483678ca686e -> ok
-OUTS cdb=3b060019c000004000000000 len=16384 sha256=ec4915d3618c08f02da59c51f1ef0b876afc7ac9833cd33042131f4f36942b54 -> ok
-OUTS cdb=3b06001a0000004000000000 len=16384 sha256=66ae784b3f77ebd811c709eded825826224e00d4effb54095d21f4bd95087713 -> ok
-OUTS cdb=3b06001a4000004000000000 len=16384 sha256=ba088998c67981f0e76e8a687a79453a38426c07888d1567634fe52dce8a2224 -> ok
-OUTS cdb=3b06001a8000004000000000 len=16384 sha256=dcb670255e5d37669c98ca6da2e6c86edecafe74f72089702f550a60145e3059 -> ok
-OUTS cdb=3b06001ac000004000000000 len=16384 sha256=e0446767fe1fc6f8f100ff74f81f03532397b64b396cc891f15e9295d110301e -> ok
-OUTS cdb=3b06001b0000004000000000 len=16384 sha256=c043e92f0d087880ba6f447207f44167820c9d5cab42321a617cb9aec4e64621 -> ok
-OUTS cdb=3b06001b4000004000000000 len=16384 sha256=68a6e257a38241fc428e086abc175b9d2c300d0d1436433704365134d9b59d5a -> ok
-OUTS cdb=3b06001b8000004000000000 len=16384 sha256=6dd776c1f7a0451aad307bee11a43b04c90883ddcb56e9a0599157869df37fe6 -> ok
-OUTS cdb=3b06001bc000004000000000 len=16384 sha256=5a79939f7f264a8d78f05ad482c80f72f3aeb24e169a8322e6323447b1d32e47 -> ok
-OUTS cdb=3b06001c0000004000000000 len=16384 sha256=7b25926781e3520cb9246f045fe42e2fbaebbd675952f22a70357a2f6d1cf11c -> ok
-OUTS cdb=3b06001c4000004000000000 len=16384 sha256=1860ceeeb5c22027bb5085e24623275b3bfd6d6bfe289f058ddb491a88d391e8 -> ok
-OUTS cdb=3b06001c8000004000000000 len=16384 sha256=f8ddbb435f06773c13ffd28cd8035321208abb57eac5ad07f161578f5a3ccda9 -> ok
-OUTS cdb=3b06001cc000004000000000 len=16384 sha256=6cc2b514c1b33f4d9b2a947d25e6119f850e731b9c1b75bd00f6c22469bedf41 -> ok
-OUTS cdb=3b06001d0000004000000000 len=16384 sha256=36ef4d806392f5abc0e99b0bc07b1161defba6c483bf2341617cdf03178c4edb -> ok
-OUTS cdb=3b06001d4000004000000000 len=16384 sha256=f3745bb34900cc3e540238ca3cf60bd82584f69417b2ef809ea6512dca89bbc4 -> ok
-OUTS cdb=3b06001d8000004000000000 len=16384 sha256=b93765384ee574205f3e89db93ff0a3c4e796a4556d3aeddf221f48c89412bf0 -> ok
-OUTS cdb=3b06001dc000004000000000 len=16384 sha256=196fac16919ac5c9b5583c0b1f8619a0297cd055cf1e6505019c4bc671b056e8 -> ok
-OUTS cdb=3b06001e0000004000000000 len=16384 sha256=65bdd7438ba6b584f1f28042bcde60815b66cfb0d27dfd0aa24bbf355dd1da19 -> ok
-OUTS cdb=3b06001e4000004000000000 len=16384 sha256=f68e29b04efb7ec0a8a014208c1a8cf668b633acf7072d093874ee18bf5c2935 -> ok
-OUTS cdb=3b06001e8000004000000000 len=16384 sha256=6bda2d35c4e64ba776b241af9283cea7272c5aa7bed188c9e309ad718e09b637 -> ok
-OUTS cdb=3b06001ec000004000000000 len=16384 sha256=c7e8e1b6ba8a505567602a543f603fd7119c9ebe2b7618281648cb264c636579 -> ok
-OUTS cdb=3b06001f0000004000000000 len=16384 sha256=c458649d5497bea82a478eeaa6f4e5a4a5b1114875e62aac7e10a9a145b1bdd5 -> ok
-OUTS cdb=3b06001f4000004000000000 len=16384 sha256=6abf2f2ba02753660f4e02ad18132bacf2095fdba4c6987ba6f08e7e75170d18 -> ok
-OUTS cdb=3b06001f8000004000000000 len=16384 sha256=eb2821519c88d4eab864a8d2c05aad7903dcaa912dfff5960906523a84a58826 -> ok
-OUTS cdb=3b06001fc000004000000000 len=16384 sha256=278ccc0ed1ec62854823f36a5900a395f8eb7243260d072573528930f665678a -> ok
-OUTS cdb=3b0700000000000000001b12 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-IN   cdb=000000000000000000000000 alloc=0 -> ok 0
-IN   cdb=030000108000000000000000 alloc=16 -> ok 16
-IN   cdb=000000000000000000000000 alloc=0 -> ok 0
-IN   cdb=030000108000000000000000 alloc=16 -> ok 16
-IN   cdb=3c060000000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060000400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060000800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060000c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060001000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060001400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060001800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060001c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060002000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060002400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060002800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060002c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060003000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060003400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060003800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060003c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060004000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060004400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060004800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060004c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060005000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060005400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060005800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060005c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060006000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060006400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060006800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060006c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060007000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060007400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060007800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060007c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060008000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060008400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060008800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060008c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060009000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060009400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060009800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060009c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000a000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000a400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000a800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000ac00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000b000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000b400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000b800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000bc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000c000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000c400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000c800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000cc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000d000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000d400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000d800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000dc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000e000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000e400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000e800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000ec00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000f000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000f400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000f800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000fc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060010000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060010400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060010800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060010c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060011000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060011400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060011800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060011c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060012000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060012400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060012800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060012c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060013000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060013400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060013800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060013c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060014000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060014400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060014800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060014c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060015000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060015400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060015800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060015c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060016000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060016400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060016800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060016c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060017000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060017400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060017800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060017c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060018000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060018400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060018800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060018c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060019000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060019400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060019800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060019c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001a000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001a400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001a800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001ac00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001b000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001b400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001b800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001bc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001c000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001c400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001c800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001cc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001d000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001d400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001d800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001dc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001e000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001e400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001e800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001ec00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001f000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001f400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001f800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001fc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060000300000002000 alloc=32 -> ok 32
-saved pre-flash backup: 2097152 bytes sha256=338b5617b5cb86838c4808828a99e8e61531b9b20c69f4a66dcb3c56537839bb
+saved pre-flash backup: <not created>
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

### MTK execute: raw drive read as input
reason: R3
```diff
-result: OK
---- text (221) ---
-reading drive memory: 0%
-reading drive memory: 1%
-reading drive memory: 2%
-reading drive memory: 3%
-reading drive memory: 4%
-reading drive memory: 5%
-reading drive memory: 6%
-reading drive memory: 7%
-reading drive memory: 8%
-reading drive memory: 9%
-reading drive memory: 10%
-reading drive memory: 11%
-reading drive memory: 12%
-reading drive memory: 13%
-reading drive memory: 14%
-reading drive memory: 15%
-reading drive memory: 16%
-reading drive memory: 17%
-reading drive memory: 18%
-reading drive memory: 19%
-reading drive memory: 20%
-reading drive memory: 21%
-reading drive memory: 22%
-reading drive memory: 23%
-reading drive memory: 24%
-reading drive memory: 25%
-reading drive memory: 26%
-reading drive memory: 27%
-reading drive memory: 28%
-reading drive memory: 29%
-reading drive memory: 30%
-reading drive memory: 31%
-reading drive memory: 32%
-reading drive memory: 33%
-reading drive memory: 34%
-reading drive memory: 35%
-reading drive memory: 36%
-reading drive memory: 37%
-reading drive memory: 38%
-reading drive memory: 39%
-reading drive memory: 40%
-reading drive memory: 41%
-reading drive memory: 42%
-reading drive memory: 43%
-reading drive memory: 44%
-reading drive memory: 45%
-reading drive memory: 46%
-reading drive memory: 47%
-reading drive memory: 48%
-reading drive memory: 49%
-reading drive memory: 50%
-reading drive memory: 51%
-reading drive memory: 52%
-reading drive memory: 53%
-reading drive memory: 54%
-reading drive memory: 55%
-reading drive memory: 56%
-reading drive memory: 57%
-reading drive memory: 58%
-reading drive memory: 59%
-reading drive memory: 60%
-reading drive memory: 61%
-reading drive memory: 62%
-reading drive memory: 63%
-reading drive memory: 64%
-reading drive memory: 65%
-reading drive memory: 66%
-reading drive memory: 67%
-reading drive memory: 68%
-reading drive memory: 69%
-reading drive memory: 70%
-reading drive memory: 71%
-reading drive memory: 72%
-reading drive memory: 73%
-reading drive memory: 74%
-reading drive memory: 75%
-reading drive memory: 76%
-reading drive memory: 77%
-reading drive memory: 78%
-reading drive memory: 79%
-reading drive memory: 80%
-reading drive memory: 81%
-reading drive memory: 82%
-reading drive memory: 83%
-reading drive memory: 84%
-reading drive memory: 85%
-reading drive memory: 86%
-reading drive memory: 87%
-reading drive memory: 88%
-reading drive memory: 89%
-reading drive memory: 90%
-reading drive memory: 91%
-reading drive memory: 92%
-reading drive memory: 93%
-reading drive memory: 94%
-reading drive memory: 95%
-reading drive memory: 96%
-reading drive memory: 97%
-reading drive memory: 98%
-reading drive memory: 99%
-reading drive memory: 100%
-== flash plan ==
-device: mock://in-memory
-drive: BU40N
-firmware: 2 MiB (plaintext envelope)
-backup: saved <TMP>/flash-execute/refused_36.tar (2097152 bytes)
-upload:    2 MiB streamed verbatim as 128 x 16 KiB chunks, then commit + verify
-
-  ** POINT OF NO RETURN **
-  The drive erases and reprograms its flash the instant the full 2 MiB upload
-  lands. This cannot be undone.
-
-EXECUTING flash — do not power off or disconnect the drive...
-flashing firmware: 0%
-flashing firmware: 1%
-flashing firmware: 2%
-flashing firmware: 3%
-flashing firmware: 4%
-flashing firmware: 5%
-flashing firmware: 6%
-flashing firmware: 7%
-flashing firmware: 8%
-flashing firmware: 9%
-flashing firmware: 10%
-flashing firmware: 11%
-flashing firmware: 12%
-flashing firmware: 13%
-flashing firmware: 14%
-flashing firmware: 15%
-flashing firmware: 16%
-flashing firmware: 17%
-flashing firmware: 18%
-flashing firmware: 19%
-flashing firmware: 20%
-flashing firmware: 21%
-flashing firmware: 22%
-flashing firmware: 23%
-flashing firmware: 24%
-flashing firmware: 25%
-flashing firmware: 26%
-flashing firmware: 27%
-flashing firmware: 28%
-flashing firmware: 29%
-flashing firmware: 30%
-flashing firmware: 31%
-flashing firmware: 32%
-flashing firmware: 33%
-flashing firmware: 34%
-flashing firmware: 35%
-flashing firmware: 36%
-flashing firmware: 37%
-flashing firmware: 38%
-flashing firmware: 39%
-flashing firmware: 40%
-flashing firmware: 41%
-flashing firmware: 42%
-flashing firmware: 43%
-flashing firmware: 44%
-flashing firmware: 45%
-flashing firmware: 46%
-flashing firmware: 47%
-flashing firmware: 48%
-flashing firmware: 49%
-flashing firmware: 50%
-flashing firmware: 51%
-flashing firmware: 52%
-flashing firmware: 53%
-flashing firmware: 54%
-flashing firmware: 55%
-flashing firmware: 56%
-flashing firmware: 57%
-flashing firmware: 58%
-flashing firmware: 59%
-flashing firmware: 60%
-flashing firmware: 61%
-flashing firmware: 62%
-flashing firmware: 63%
-flashing firmware: 64%
-flashing firmware: 65%
-flashing firmware: 66%
-flashing firmware: 67%
-flashing firmware: 68%
-flashing firmware: 69%
-flashing firmware: 70%
-flashing firmware: 71%
-flashing firmware: 72%
-flashing firmware: 73%
-flashing firmware: 74%
-flashing firmware: 75%
-flashing firmware: 76%
-flashing firmware: 77%
-flashing firmware: 78%
-flashing firmware: 79%
-flashing firmware: 80%
-flashing firmware: 81%
-flashing firmware: 82%
-flashing firmware: 83%
-flashing firmware: 84%
-flashing firmware: 85%
-flashing firmware: 86%
-flashing firmware: 87%
-flashing firmware: 88%
-flashing firmware: 89%
-flashing firmware: 90%
-flashing firmware: 91%
-flashing firmware: 92%
-flashing firmware: 93%
-flashing firmware: 94%
-flashing firmware: 95%
-flashing firmware: 96%
-flashing firmware: 97%
-flashing firmware: 98%
-flashing firmware: 99%
-flashing firmware: 100%
-warning: could not parse the post-flash REQUEST SENSE response (16 bytes); relying on read-back verify
-upload complete (2 MiB); waiting for the drive to finish programming...
-warning: post-settle REQUEST SENSE returned an unparseable 16-byte reply; relying on read-back verify.
-verifying...
-  flash complete ........... 60 KiB of integrity-protected regions verified
-  Integrity is enforced on-device: the drive recomputes CMAC at boot and rejects a bad image. The firmware identity below is the real result.
-firmware now: unrecognized  [0c2866a95c87305370fb6f7b2b37fdc6bab8f431cd0022625c1e40b827223668]
---- events (221) ---
-PROGRESS reading drive memory 4096/2097152
-PROGRESS reading drive memory 24576/2097152
-PROGRESS reading drive memory 45056/2097152
-PROGRESS reading drive memory 65536/2097152
-PROGRESS reading drive memory 86016/2097152
-PROGRESS reading drive memory 106496/2097152
-PROGRESS reading drive memory 126976/2097152
-PROGRESS reading drive memory 147456/2097152
-PROGRESS reading drive memory 167936/2097152
-PROGRESS reading drive memory 192512/2097152
-PROGRESS reading drive memory 212992/2097152
-PROGRESS reading drive memory 233472/2097152
-PROGRESS reading drive memory 253952/2097152
-PROGRESS reading drive memory 274432/2097152
-PROGRESS reading drive memory 294912/2097152
-PROGRESS reading drive memory 315392/2097152
-PROGRESS reading drive memory 335872/2097152
-PROGRESS reading drive memory 360448/2097152
-PROGRESS reading drive memory 380928/2097152
-PROGRESS reading drive memory 401408/2097152
-PROGRESS reading drive memory 421888/2097152
-PROGRESS reading drive memory 442368/2097152
-PROGRESS reading drive memory 462848/2097152
-PROGRESS reading drive memory 483328/2097152
-PROGRESS reading drive memory 503808/2097152
-PROGRESS reading drive memory 524288/2097152
-PROGRESS reading drive memory 548864/2097152
-PROGRESS reading drive memory 569344/2097152
-PROGRESS reading drive memory 589824/2097152
-PROGRESS reading drive memory 610304/2097152
-PROGRESS reading drive memory 630784/2097152
-PROGRESS reading drive memory 651264/2097152
-PROGRESS reading drive memory 671744/2097152
-PROGRESS reading drive memory 692224/2097152
-PROGRESS reading drive memory 716800/2097152
-PROGRESS reading drive memory 737280/2097152
-PROGRESS reading drive memory 757760/2097152
-PROGRESS reading drive memory 778240/2097152
-PROGRESS reading drive memory 798720/2097152
-PROGRESS reading drive memory 819200/2097152
-PROGRESS reading drive memory 839680/2097152
-PROGRESS reading drive memory 860160/2097152
-PROGRESS reading drive memory 884736/2097152
-PROGRESS reading drive memory 905216/2097152
-PROGRESS reading drive memory 925696/2097152
-PROGRESS reading drive memory 946176/2097152
-PROGRESS reading drive memory 966656/2097152
-PROGRESS reading drive memory 987136/2097152
-PROGRESS reading drive memory 1007616/2097152
-PROGRESS reading drive memory 1028096/2097152
-PROGRESS reading drive memory 1048576/2097152
-PROGRESS reading drive memory 1073152/2097152
-PROGRESS reading drive memory 1093632/2097152
-PROGRESS reading drive memory 1114112/2097152
-PROGRESS reading drive memory 1134592/2097152
-PROGRESS reading drive memory 1155072/2097152
-PROGRESS reading drive memory 1175552/2097152
-PROGRESS reading drive memory 1196032/2097152
-PROGRESS reading drive memory 1216512/2097152
-PROGRESS reading drive memory 1241088/2097152
-PROGRESS reading drive memory 1261568/2097152
-PROGRESS reading drive memory 1282048/2097152
-PROGRESS reading drive memory 1302528/2097152
-PROGRESS reading drive memory 1323008/2097152
-PROGRESS reading drive memory 1343488/2097152
-PROGRESS reading drive memory 1363968/2097152
-PROGRESS reading drive memory 1384448/2097152
-PROGRESS reading drive memory 1409024/2097152
-PROGRESS reading drive memory 1429504/2097152
-PROGRESS reading drive memory 1449984/2097152
-PROGRESS reading drive memory 1470464/2097152
-PROGRESS reading drive memory 1490944/2097152
-PROGRESS reading drive memory 1511424/2097152
-PROGRESS reading drive memory 1531904/2097152
-PROGRESS reading drive memory 1552384/2097152
-PROGRESS reading drive memory 1572864/2097152
-PROGRESS reading drive memory 1597440/2097152
-PROGRESS reading drive memory 1617920/2097152
-PROGRESS reading drive memory 1638400/2097152
-PROGRESS reading drive memory 1658880/2097152
-PROGRESS reading drive memory 1679360/2097152
-PROGRESS reading drive memory 1699840/2097152
-PROGRESS reading drive memory 1720320/2097152
-PROGRESS reading drive memory 1740800/2097152
-PROGRESS reading drive memory 1765376/2097152
-PROGRESS reading drive memory 1785856/2097152
-PROGRESS reading drive memory 1806336/2097152
-PROGRESS reading drive memory 1826816/2097152
-PROGRESS reading drive memory 1847296/2097152
-PROGRESS reading drive memory 1867776/2097152
-PROGRESS reading drive memory 1888256/2097152
-PROGRESS reading drive memory 1908736/2097152
-PROGRESS reading drive memory 1933312/2097152
-PROGRESS reading drive memory 1953792/2097152
-PROGRESS reading drive memory 1974272/2097152
-PROGRESS reading drive memory 1994752/2097152
-PROGRESS reading drive memory 2015232/2097152
-PROGRESS reading drive memory 2035712/2097152
-PROGRESS reading drive memory 2056192/2097152
-PROGRESS reading drive memory 2076672/2097152
-PROGRESS reading drive memory 2097152/2097152
-MSG      == flash plan ==
-MSG      device: mock://in-memory
-MSG      drive: BU40N
-MSG      firmware: 2 MiB (plaintext envelope)
-MSG      backup: saved <TMP>/flash-execute/refused_36.tar (2097152 bytes)
-MSG      upload:    2 MiB streamed verbatim as 128 x 16 KiB chunks, then commit + verify
-MSG      
-MSG        ** POINT OF NO RETURN **
-MSG        The drive erases and reprograms its flash the instant the full 2 MiB upload
-MSG        lands. This cannot be undone.
-MSG      
-MSG      EXECUTING flash — do not power off or disconnect the drive...
-PROGRESS flashing firmware 16384/2097152
-PROGRESS flashing firmware 32768/2097152
-PROGRESS flashing firmware 49152/2097152
-PROGRESS flashing firmware 65536/2097152
-PROGRESS flashing firmware 98304/2097152
-PROGRESS flashing firmware 114688/2097152
-PROGRESS flashing firmware 131072/2097152
-PROGRESS flashing firmware 147456/2097152
-PROGRESS flashing firmware 180224/2097152
-PROGRESS flashing firmware 196608/2097152
-PROGRESS flashing firmware 212992/2097152
-PROGRESS flashing firmware 245760/2097152
-PROGRESS flashing firmware 262144/2097152
-PROGRESS flashing firmware 278528/2097152
-PROGRESS flashing firmware 294912/2097152
-PROGRESS flashing firmware 327680/2097152
-PROGRESS flashing firmware 344064/2097152
-PROGRESS flashing firmware 360448/2097152
-PROGRESS flashing firmware 393216/2097152
-PROGRESS flashing firmware 409600/2097152
-PROGRESS flashing firmware 425984/2097152
-PROGRESS flashing firmware 442368/2097152
-PROGRESS flashing firmware 475136/2097152
-PROGRESS flashing firmware 491520/2097152
-PROGRESS flashing firmware 507904/2097152
-PROGRESS flashing firmware 524288/2097152
-PROGRESS flashing firmware 557056/2097152
-PROGRESS flashing firmware 573440/2097152
-PROGRESS flashing firmware 589824/2097152
-PROGRESS flashing firmware 622592/2097152
-PROGRESS flashing firmware 638976/2097152
-PROGRESS flashing firmware 655360/2097152
-PROGRESS flashing firmware 671744/2097152
-PROGRESS flashing firmware 704512/2097152
-PROGRESS flashing firmware 720896/2097152
-PROGRESS flashing firmware 737280/2097152
-PROGRESS flashing firmware 770048/2097152
-PROGRESS flashing firmware 786432/2097152
-PROGRESS flashing firmware 802816/2097152
-PROGRESS flashing firmware 819200/2097152
-PROGRESS flashing firmware 851968/2097152
-PROGRESS flashing firmware 868352/2097152
-PROGRESS flashing firmware 884736/2097152
-PROGRESS flashing firmware 917504/2097152
-PROGRESS flashing firmware 933888/2097152
-PROGRESS flashing firmware 950272/2097152
-PROGRESS flashing firmware 966656/2097152
-PROGRESS flashing firmware 999424/2097152
-PROGRESS flashing firmware 1015808/2097152
-PROGRESS flashing firmware 1032192/2097152
-PROGRESS flashing firmware 1048576/2097152
-PROGRESS flashing firmware 1081344/2097152
-PROGRESS flashing firmware 1097728/2097152
-PROGRESS flashing firmware 1114112/2097152
-PROGRESS flashing firmware 1146880/2097152
-PROGRESS flashing firmware 1163264/2097152
-PROGRESS flashing firmware 1179648/2097152
-PROGRESS flashing firmware 1196032/2097152
-PROGRESS flashing firmware 1228800/2097152
-PROGRESS flashing firmware 1245184/2097152
-PROGRESS flashing firmware 1261568/2097152
-PROGRESS flashing firmware 1294336/2097152
-PROGRESS flashing firmware 1310720/2097152
-PROGRESS flashing firmware 1327104/2097152
-PROGRESS flashing firmware 1343488/2097152
-PROGRESS flashing firmware 1376256/2097152
-PROGRESS flashing firmware 1392640/2097152
-PROGRESS flashing firmware 1409024/2097152
-PROGRESS flashing firmware 1441792/2097152
-PROGRESS flashing firmware 1458176/2097152
-PROGRESS flashing firmware 1474560/2097152
-PROGRESS flashing firmware 1490944/2097152
-PROGRESS flashing firmware 1523712/2097152
-PROGRESS flashing firmware 1540096/2097152
-PROGRESS flashing firmware 1556480/2097152
-PROGRESS flashing firmware 1572864/2097152
-PROGRESS flashing firmware 1605632/2097152
-PROGRESS flashing firmware 1622016/2097152
-PROGRESS flashing firmware 1638400/2097152
-PROGRESS flashing firmware 1671168/2097152
-PROGRESS flashing firmware 1687552/2097152
-PROGRESS flashing firmware 1703936/2097152
-PROGRESS flashing firmware 1720320/2097152
-PROGRESS flashing firmware 1753088/2097152
-PROGRESS flashing firmware 1769472/2097152
-PROGRESS flashing firmware 1785856/2097152
-PROGRESS flashing firmware 1818624/2097152
-PROGRESS flashing firmware 1835008/2097152
-PROGRESS flashing firmware 1851392/2097152
-PROGRESS flashing firmware 1867776/2097152
-PROGRESS flashing firmware 1900544/2097152
-PROGRESS flashing firmware 1916928/2097152
-PROGRESS flashing firmware 1933312/2097152
-PROGRESS flashing firmware 1966080/2097152
-PROGRESS flashing firmware 1982464/2097152
-PROGRESS flashing firmware 1998848/2097152
-PROGRESS flashing firmware 2015232/2097152
-PROGRESS flashing firmware 2048000/2097152
-PROGRESS flashing firmware 2064384/2097152
-PROGRESS flashing firmware 2080768/2097152
-PROGRESS flashing firmware 2097152/2097152
-MSG      warning: could not parse the post-flash REQUEST SENSE response (16 bytes); relying on read-back verify
-MSG      upload complete (2 MiB); waiting for the drive to finish programming...
-MSG      warning: post-settle REQUEST SENSE returned an unparseable 16-byte reply; relying on read-back verify.
-MSG      verifying...
-MSG        flash complete ........... 60 KiB of integrity-protected regions verified
-MSG        Integrity is enforced on-device: the drive recomputes CMAC at boot and rejects a bad image. The firmware identity below is the real result.
-MSG      firmware now: unrecognized  [0c2866a95c87305370fb6f7b2b37fdc6bab8f431cd0022625c1e40b827223668]
---- scsi transcript (784) ---
-MEDIUM -> ClosedEmpty
-IN   cdb=3c060000000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060000f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060001f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060002f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060003f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060004f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060005f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060006f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060007f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060008f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060009f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000a900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000aa00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ab00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ac00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ad00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ae00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000af00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000b900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ba00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000bb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000bc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000bd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000be00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000bf00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000c900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ca00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000cb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000cc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000cd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ce00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000cf00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000d900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000da00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000db00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000dc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000dd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000de00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000df00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000e900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ea00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000eb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ec00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ed00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ee00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ef00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000f900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000fa00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000fb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000fc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000fd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000fe00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06000ff00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060010f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060011f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060012f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060013f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060014f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060015f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060016f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060017f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060018f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019a00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019b00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019c00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019d00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019e00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c060019f00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001a900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001aa00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ab00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ac00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ad00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ae00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001af00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001b900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ba00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001bb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001bc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001bd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001be00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001bf00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001c900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ca00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001cb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001cc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001cd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ce00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001cf00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001d900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001da00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001db00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001dc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001dd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001de00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001df00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001e900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ea00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001eb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ec00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ed00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ee00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ef00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f000000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f100000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f200000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f300000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f400000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f500000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f600000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f700000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f800000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001f900000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001fa00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001fb00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001fc00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001fd00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001fe00000100000 alloc=4096 -> ok 4096
-IN   cdb=3c06001ff00000100000 alloc=4096 -> ok 4096
-IN   cdb=120000006000 alloc=96 -> ok 96
-IN   cdb=3c060000300000002000 alloc=32 -> ok 32
-IN   cdb=120000006000 alloc=96 -> ok 96
-IN   cdb=3c060000300000002000 alloc=32 -> ok 32
+result: ERR this is a raw drive read (its boot page is the read-back copy), not a flashable image — refusing to flash. Restore from a freemkv backup .bin, or the vendor's update image. This gate cannot be overridden.
+--- text (0) ---
+--- events (0) ---
+--- scsi transcript (1) ---
-IN   cdb=3c06001ec000000100000000 alloc=256 -> ok 256
-IN   cdb=000000000000000000000000 alloc=0 -> ok 0
-OUTS cdb=3b01000000000000000b0000 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-OUTS cdb=3b0600000000004000000000 len=16384 sha256=d6ba40c689b1b69aa225cc08c5f0acde6a21058ff1f610cd2bcee3be742a5b0a -> ok
-OUTS cdb=3b0600004000004000000000 len=16384 sha256=e720708b81e40bf2bc273cbf9a593fa8e07050b600b71e89ef096fff9dfd27e8 -> ok
-OUTS cdb=3b0600008000004000000000 len=16384 sha256=5f68c6f9da037e85ca27b5b0f3f7d790da2cf8b43d905cc963b329a91751ca5d -> ok
-OUTS cdb=3b060000c000004000000000 len=16384 sha256=080ce19ee0ed294c5288f49426902263e96366a84d414412ad1eeb3dbc5cb5f5 -> ok
-OUTS cdb=3b0600010000004000000000 len=16384 sha256=0a73933b9c89ab464c4b805e9abe1d1a750669a6c97a03de25e311b83198f00c -> ok
-OUTS cdb=3b0600014000004000000000 len=16384 sha256=f15ee21e81e678cfe8e5b6784ecc43f0eaa5b2f5981bb77b0d853718c414d07d -> ok
-OUTS cdb=3b0600018000004000000000 len=16384 sha256=095f37811f34315fe0e57b6d042b1fb7af8f7ecc85a468d78e5732492becb8af -> ok
-OUTS cdb=3b060001c000004000000000 len=16384 sha256=d3caa063844f2ede22d6a7202859f1e8d00c76a1722c2defac0d886463befb89 -> ok
-OUTS cdb=3b0600020000004000000000 len=16384 sha256=94e09640e0a46706d3270fae71e3f18f8c43b9e3d519cc9270a83b4fb3c88aef -> ok
-OUTS cdb=3b0600024000004000000000 len=16384 sha256=0690a5b4ac8fd5e3730df08890efabc4d920eab482cd47defed991a5489a71af -> ok
-OUTS cdb=3b0600028000004000000000 len=16384 sha256=7c378ae5769dea4d7f4e29f18e8717f10c26e8e416e8da1df860c79a0d630dda -> ok
-OUTS cdb=3b060002c000004000000000 len=16384 sha256=cb03a33c6600367b988298792946c72309c2497667b430b6acc152759a808ed4 -> ok
-OUTS cdb=3b0600030000004000000000 len=16384 sha256=3259933e1118189cc5495fca40ebbdd9944f998db8c835cf98e8327d826fd47d -> ok
-OUTS cdb=3b0600034000004000000000 len=16384 sha256=dac75e8748dfe828ffae864a2a4dc4c8c64fdc5e7a432a5852e4c8a9ba2a01b2 -> ok
-OUTS cdb=3b0600038000004000000000 len=16384 sha256=87239ec7874daa70fce81fb60065697f3b08e020e0db841a1c3482c6fc0509db -> ok
-OUTS cdb=3b060003c000004000000000 len=16384 sha256=7e439ccbd202207731a447cb5d399bba513cb0aa41cb4fc4f62c5a387f62fcf0 -> ok
-OUTS cdb=3b0600040000004000000000 len=16384 sha256=cb4d76c10027e9a93d5a1eb2b7b4f2bdbd2127fef966d9c801f45419f6d68354 -> ok
-OUTS cdb=3b0600044000004000000000 len=16384 sha256=33a2fc9dcef97f06d18f3312a638caec0b6b4159ceb778fc012354ec48856697 -> ok
-OUTS cdb=3b0600048000004000000000 len=16384 sha256=b92893a270a49768d5408808152497cc7e0bec8e963feb9afe1e4afbccf830d4 -> ok
-OUTS cdb=3b060004c000004000000000 len=16384 sha256=1cb9443027db701c585e5a355513f4e5a60f5d34fd9d7e58bf62d90e22e1eb8e -> ok
-OUTS cdb=3b0600050000004000000000 len=16384 sha256=9e418613f72f1cf26ce556fe99735e345132db5227a100d00e49bc7ed71131a1 -> ok
-OUTS cdb=3b0600054000004000000000 len=16384 sha256=f6512e82635974095f07dea2df4c66fa88e590f86c4ed861a24ab01de3a02187 -> ok
-OUTS cdb=3b0600058000004000000000 len=16384 sha256=6b69bf723bf0cd9f54773ef8c0932a1a46ba21fde7251812650291ac467fe46c -> ok
-OUTS cdb=3b060005c000004000000000 len=16384 sha256=f0ff4a64cbf90ad5f2e4f4e243ea46e5333ab26ebf1888fdeed19f29522f1f18 -> ok
-OUTS cdb=3b0600060000004000000000 len=16384 sha256=8fc14867ea42217024871f0f06e747708346929723da7a7547b0290fae5cddd7 -> ok
-OUTS cdb=3b0600064000004000000000 len=16384 sha256=2c01b0f1ed09608d7fd9384e0d8d5bfde05864d50216753411c88e154ee4cb7f -> ok
-OUTS cdb=3b0600068000004000000000 len=16384 sha256=bee6a2ab268c601c9ed80d6156985c897d2689d6f0aa7879e66ee7ba3a55d302 -> ok
-OUTS cdb=3b060006c000004000000000 len=16384 sha256=609c0438cee13ca9159830268bad51e1e9f9236eb9b192440ff551d0ff958ab6 -> ok
-OUTS cdb=3b0600070000004000000000 len=16384 sha256=ecb48a2c92d5214aa01d928db20e2c28fedadfea3d2df5700e2b895ea2bec42c -> ok
-OUTS cdb=3b0600074000004000000000 len=16384 sha256=be47ce9cb6c6a55468a3591aafcce7f889280af5d44dd55f470f3e4fd51d13b4 -> ok
-OUTS cdb=3b0600078000004000000000 len=16384 sha256=6db0b02515c6e901511426198ce8f94406b01e69a5cf3f9d1328f525135e2e0a -> ok
-OUTS cdb=3b060007c000004000000000 len=16384 sha256=158b5818a6ae049107b9ee1736bc0fcc8d318af59c20525eb5bd010fcd4bd127 -> ok
-OUTS cdb=3b0600080000004000000000 len=16384 sha256=7acc6f262c0c05e6d49c5b67ef1555b19cd2726e09b5b16b3700f6ecf8bcf177 -> ok
-OUTS cdb=3b0600084000004000000000 len=16384 sha256=485fae2016758d3ff932f7c0e40d9917aab8d228a59fc011fb8dc391365d060b -> ok
-OUTS cdb=3b0600088000004000000000 len=16384 sha256=f0145e1d11e9c9ea56bd0397c1e8f50be48e93f793dee8a867de1faed8f120b0 -> ok
-OUTS cdb=3b060008c000004000000000 len=16384 sha256=3a359a6bf129de0dc0300a39c32b7d8f3938cf6c4191dd1cdb30fd9ee10d6e5d -> ok
-OUTS cdb=3b0600090000004000000000 len=16384 sha256=4270023173a8053d3de2f017b0ff8daf20dfd31ea2d1a16507d7a48ca9a0605a -> ok
-OUTS cdb=3b0600094000004000000000 len=16384 sha256=73e344d671b34c0c713411629cfc33e6dce56354624907299c80715c021dc4b9 -> ok
-OUTS cdb=3b0600098000004000000000 len=16384 sha256=32b18839bce5454576d1d5cfa4e619aee37704dc0c55fe602e3fdd805decb2d0 -> ok
-OUTS cdb=3b060009c000004000000000 len=16384 sha256=1d03ed5ecec080eb58aa01fcc6dcb2930cb28b9982fbd10e1a102e078753b856 -> ok
-OUTS cdb=3b06000a0000004000000000 len=16384 sha256=7991f182db4dd3c493829bb98af2471f0fc5ef6b81b31402d76b316ba7fb79e2 -> ok
-OUTS cdb=3b06000a4000004000000000 len=16384 sha256=b745869c66c78e322f603cbc821519a61faf96ec242b09680c6e6a5400267fc2 -> ok
-OUTS cdb=3b06000a8000004000000000 len=16384 sha256=d4dab7bf9d391d6f8a5f4c91ea956207acc5e45ea076d111be14c0cb0b828943 -> ok
-OUTS cdb=3b06000ac000004000000000 len=16384 sha256=cb7d7fd76204b2ebce1d5004171f125c7bd581bfa7adb55bd8417da4a79eec01 -> ok
-OUTS cdb=3b06000b0000004000000000 len=16384 sha256=a4e6ae369e9493e932ecc9dfa030dbac8683d91f6db96d0b11ffd7f2f32e5000 -> ok
-OUTS cdb=3b06000b4000004000000000 len=16384 sha256=5e4d145ea6bbcaf5d05cd822ccd23f18f99277cc11703b92310a5808a074d297 -> ok
-OUTS cdb=3b06000b8000004000000000 len=16384 sha256=e884fec69679709c3862c0226c6208cb38b852d9c57c5103b1c78bced0f615af -> ok
-OUTS cdb=3b06000bc000004000000000 len=16384 sha256=532e9a3d1991b98c7ab64a1f988a55595230b632ce47ec20963bd1b6f00f346b -> ok
-OUTS cdb=3b06000c0000004000000000 len=16384 sha256=4ae3e07219d40826ff9228dcb322c4ef90363d038550f7270e008a2ed138522c -> ok
-OUTS cdb=3b06000c4000004000000000 len=16384 sha256=ad0865a82b1c4110229ddcb66e9da258182393eb85d5ad5f0dd2cb4f57c3a903 -> ok
-OUTS cdb=3b06000c8000004000000000 len=16384 sha256=a1c890278a9c0be38f9721289437cede743e5a62b3c02963521ed147468c5ccc -> ok
-OUTS cdb=3b06000cc000004000000000 len=16384 sha256=0478fa543cbee0b06880c7b97358b6767ac42a58afd22d7d345085076332bb97 -> ok
-OUTS cdb=3b06000d0000004000000000 len=16384 sha256=1fa6c7e411e4553b24b0bb04a42c8bc7d064b471cdc43664ba7beb87f0e9273f -> ok
-OUTS cdb=3b06000d4000004000000000 len=16384 sha256=aaf35a2309dbf2ad9a0d782ab90947ced394740601999f1fc1436a1857b36812 -> ok
-OUTS cdb=3b06000d8000004000000000 len=16384 sha256=a2849a643b4d1485eeffee70f0afb20cbfdafb09f2685edc363feec4fc59d218 -> ok
-OUTS cdb=3b06000dc000004000000000 len=16384 sha256=b33bf0d4cdcc332203a65132ec2f295f94527949a1c51ae352cf71f877f27375 -> ok
-OUTS cdb=3b06000e0000004000000000 len=16384 sha256=27b079ab901405164052d4d130239c8833b5689f34c0faf9926e720622e9377f -> ok
-OUTS cdb=3b06000e4000004000000000 len=16384 sha256=5b03db3c8b66594d0fd1a840ba89fda9ead4ed3ef7a774a8a8d6e51fa6fe126a -> ok
-OUTS cdb=3b06000e8000004000000000 len=16384 sha256=c0173ed2edfcf169b166c044527792527d018ed49ec635b9edfcefe0efcf8f9a -> ok
-OUTS cdb=3b06000ec000004000000000 len=16384 sha256=95186e7e174007c434849f7d81730348cdd036be0636c02c67fc4d4715bb7859 -> ok
-OUTS cdb=3b06000f0000004000000000 len=16384 sha256=2eff5a364a1a80d7bf4c43f684109a637fa91d51f11bc02abe4c2b53d195560d -> ok
-OUTS cdb=3b06000f4000004000000000 len=16384 sha256=24b845027e96d2fc8762a1d1eab4d3a2b2b5f5babf762a54294b9d4b92aac66d -> ok
-OUTS cdb=3b06000f8000004000000000 len=16384 sha256=c49472228fd90803fffe6d7e0c16f5a805447d7f3edfe80871562eb91451490b -> ok
-OUTS cdb=3b06000fc000004000000000 len=16384 sha256=9d3ed927374cabed71d341c79fd3840da027533d19312493fb757656cb4b4373 -> ok
-OUTS cdb=3b0600100000004000000000 len=16384 sha256=20fc3f3bf93f6f8890154e05cb8134c7c0919ae58bd7d81f2b572820ff21cc58 -> ok
-OUTS cdb=3b0600104000004000000000 len=16384 sha256=029c549c5707d66a8c9339937d61711959c6db8767375e62d29ee5c4a48dbdb6 -> ok
-OUTS cdb=3b0600108000004000000000 len=16384 sha256=f7ebd45b0948d1e02213bf2acd1b754af41d279dc00c978dbd67982050d2190b -> ok
-OUTS cdb=3b060010c000004000000000 len=16384 sha256=e7a184e6e90a58c76112c52e5027f0f43b40b078ced62fc62752ead1936ee2ad -> ok
-OUTS cdb=3b0600110000004000000000 len=16384 sha256=afddb69baba0cfe5e4abc6e8a1377cd976cf78922361c6fde815892fa8802882 -> ok
-OUTS cdb=3b0600114000004000000000 len=16384 sha256=55cdd4e5f323be2983795df6963bd0f27e4225608a2df723b27a7eeb457b948b -> ok
-OUTS cdb=3b0600118000004000000000 len=16384 sha256=64eafd53000bfa32de277eb0e9aaaaed4748af7fe34deeb90abcce9dc9cbb7f2 -> ok
-OUTS cdb=3b060011c000004000000000 len=16384 sha256=ddd3e3f02938b51a3c6cc036b1f1fd801c2a8026fa455ecba5ea7b4f581c7545 -> ok
-OUTS cdb=3b0600120000004000000000 len=16384 sha256=783700293aa48fb2bfe085b411129179edbe77d37f5a17855d351e3f9f299d18 -> ok
-OUTS cdb=3b0600124000004000000000 len=16384 sha256=5a4b9b2978e03fb758b65cf06e551fec3d6de846d417fbb541b33019a0ca5d80 -> ok
-OUTS cdb=3b0600128000004000000000 len=16384 sha256=c53e704410588b384ee4614671f4f7a03fd6da619d69ca858d489f359023b409 -> ok
-OUTS cdb=3b060012c000004000000000 len=16384 sha256=de0cf267e239d09d2c32daf2e7134430d12cd7ce2602eb4ae77d77c165a556a5 -> ok
-OUTS cdb=3b0600130000004000000000 len=16384 sha256=e92a8df3f0dc66f759e416e5716d28dd321d75f3b4642f3b44e3cc7780a55fba -> ok
-OUTS cdb=3b0600134000004000000000 len=16384 sha256=7c233790cbc163fd9e4770a40cd53646c783dd880786d647c64326726f83b657 -> ok
-OUTS cdb=3b0600138000004000000000 len=16384 sha256=52955c3a17d0aff9046d9ba2bc72ed242c8f023bd19f1984d7ec1360597c5a87 -> ok
-OUTS cdb=3b060013c000004000000000 len=16384 sha256=95b8f141482bc7c0fd339057aec0a8af02522d34dc47609e0224f9b579f8c08b -> ok
-OUTS cdb=3b0600140000004000000000 len=16384 sha256=6b0a1b9f12ca5e9b2fec679fc3004b9b2f495a56cb60ed3907e84c79c02c492d -> ok
-OUTS cdb=3b0600144000004000000000 len=16384 sha256=42562753522cd4988909dd1e5ee0b56e4c5e314b6803375869475c155bf8419f -> ok
-OUTS cdb=3b0600148000004000000000 len=16384 sha256=86201eec1646bd16fe3b32ede3263b993d3c80301520928898b954610a92856b -> ok
-OUTS cdb=3b060014c000004000000000 len=16384 sha256=d484412443264e0b58ed89d9a8bb20088adf4fc1c96b02d64dd3e23e8dec665e -> ok
-OUTS cdb=3b0600150000004000000000 len=16384 sha256=6765325c656b3b59f19d1bb06a1dc7b7349e29144a70c02e12759225eb2615ae -> ok
-OUTS cdb=3b0600154000004000000000 len=16384 sha256=6742891b2341162648d91b7e02987de6a7d7d00ea20c6ac0762e9f784a9632e8 -> ok
-OUTS cdb=3b0600158000004000000000 len=16384 sha256=bc297804ebc261153f9f3a15b732efffd0aaa9a962fed61f117648d48185b807 -> ok
-OUTS cdb=3b060015c000004000000000 len=16384 sha256=610e3f8421990bb93e32ea3fd6466917088d0cc9419b352cc9b1be3daba7ef3a -> ok
-OUTS cdb=3b0600160000004000000000 len=16384 sha256=1717eb869b97fed6a9aa882d8040085045647cb545dd2535552e29e5f2cda0ce -> ok
-OUTS cdb=3b0600164000004000000000 len=16384 sha256=219be172635dde3263cc305ca67b9d61756a9343b72fd76beadbf8b610b3695c -> ok
-OUTS cdb=3b0600168000004000000000 len=16384 sha256=28c710a0bbde3a9908046bf265e35e18fac40e490071f9ae57b5d214a1fee4d6 -> ok
-OUTS cdb=3b060016c000004000000000 len=16384 sha256=8b69e9a0ecdfcb48a30abf92079864bac8f5bb6b710ea9ca255876177a97f53f -> ok
-OUTS cdb=3b0600170000004000000000 len=16384 sha256=da49ab8e54a9789d1e540fc629b257d16969e71385230969a7e142162e1dd390 -> ok
-OUTS cdb=3b0600174000004000000000 len=16384 sha256=b08c5a92d6ae5e52345377d06627e23f81b7f3d54fec42bd08c664c6202effaa -> ok
-OUTS cdb=3b0600178000004000000000 len=16384 sha256=5085d20e964c387df925ce74e1b50ce0f968fff058338c00877ed8a550c2038a -> ok
-OUTS cdb=3b060017c000004000000000 len=16384 sha256=ac68173edac0977d997fcf03656b683c939b66e430a4f93308483ef970393402 -> ok
-OUTS cdb=3b0600180000004000000000 len=16384 sha256=b758cc1adfef79571ffd37bfd85cb597ef1f9a805804deaeb576a383c59834a1 -> ok
-OUTS cdb=3b0600184000004000000000 len=16384 sha256=cf7b69c13c7108d6769b4f17fd61ecd186a43549e07715c9be7542a082f79779 -> ok
-OUTS cdb=3b0600188000004000000000 len=16384 sha256=ea4eacb4f35343adacd0b9559447597277751fe8fd78bb50f250d426bff11c5d -> ok
-OUTS cdb=3b060018c000004000000000 len=16384 sha256=aab4332736cf0d3c9a172dadf4701372a6e8484c41d4cdda23154466913c76cd -> ok
-OUTS cdb=3b0600190000004000000000 len=16384 sha256=dec9ad020e950205872dee374970d8adead132ae8eb09549e80cd5ffcaa32693 -> ok
-OUTS cdb=3b0600194000004000000000 len=16384 sha256=9409d02bca2e6f0b9671e56f498c21e918fce8fd6c5f39471f881cfc010ee7f9 -> ok
-OUTS cdb=3b0600198000004000000000 len=16384 sha256=892a190a2b26b9a4749dc52d2044a656dfb13e961371a03ba0a6483678ca686e -> ok
-OUTS cdb=3b060019c000004000000000 len=16384 sha256=ec4915d3618c08f02da59c51f1ef0b876afc7ac9833cd33042131f4f36942b54 -> ok
-OUTS cdb=3b06001a0000004000000000 len=16384 sha256=66ae784b3f77ebd811c709eded825826224e00d4effb54095d21f4bd95087713 -> ok
-OUTS cdb=3b06001a4000004000000000 len=16384 sha256=ba088998c67981f0e76e8a687a79453a38426c07888d1567634fe52dce8a2224 -> ok
-OUTS cdb=3b06001a8000004000000000 len=16384 sha256=dcb670255e5d37669c98ca6da2e6c86edecafe74f72089702f550a60145e3059 -> ok
-OUTS cdb=3b06001ac000004000000000 len=16384 sha256=e0446767fe1fc6f8f100ff74f81f03532397b64b396cc891f15e9295d110301e -> ok
-OUTS cdb=3b06001b0000004000000000 len=16384 sha256=c043e92f0d087880ba6f447207f44167820c9d5cab42321a617cb9aec4e64621 -> ok
-OUTS cdb=3b06001b4000004000000000 len=16384 sha256=68a6e257a38241fc428e086abc175b9d2c300d0d1436433704365134d9b59d5a -> ok
-OUTS cdb=3b06001b8000004000000000 len=16384 sha256=6dd776c1f7a0451aad307bee11a43b04c90883ddcb56e9a0599157869df37fe6 -> ok
-OUTS cdb=3b06001bc000004000000000 len=16384 sha256=5a79939f7f264a8d78f05ad482c80f72f3aeb24e169a8322e6323447b1d32e47 -> ok
-OUTS cdb=3b06001c0000004000000000 len=16384 sha256=7b25926781e3520cb9246f045fe42e2fbaebbd675952f22a70357a2f6d1cf11c -> ok
-OUTS cdb=3b06001c4000004000000000 len=16384 sha256=1860ceeeb5c22027bb5085e24623275b3bfd6d6bfe289f058ddb491a88d391e8 -> ok
-OUTS cdb=3b06001c8000004000000000 len=16384 sha256=f8ddbb435f06773c13ffd28cd8035321208abb57eac5ad07f161578f5a3ccda9 -> ok
-OUTS cdb=3b06001cc000004000000000 len=16384 sha256=6cc2b514c1b33f4d9b2a947d25e6119f850e731b9c1b75bd00f6c22469bedf41 -> ok
-OUTS cdb=3b06001d0000004000000000 len=16384 sha256=36ef4d806392f5abc0e99b0bc07b1161defba6c483bf2341617cdf03178c4edb -> ok
-OUTS cdb=3b06001d4000004000000000 len=16384 sha256=f3745bb34900cc3e540238ca3cf60bd82584f69417b2ef809ea6512dca89bbc4 -> ok
-OUTS cdb=3b06001d8000004000000000 len=16384 sha256=00324f8fa6381796780e5f9b056de3adcdf206042ca8e1f461910592d802e3fa -> ok
-OUTS cdb=3b06001dc000004000000000 len=16384 sha256=196fac16919ac5c9b5583c0b1f8619a0297cd055cf1e6505019c4bc671b056e8 -> ok
-OUTS cdb=3b06001e0000004000000000 len=16384 sha256=fbcf622dbc94ae8b124b563d7a04c22ad75e2f84a99528de927af7e612e5ffad -> ok
-OUTS cdb=3b06001e4000004000000000 len=16384 sha256=f68e29b04efb7ec0a8a014208c1a8cf668b633acf7072d093874ee18bf5c2935 -> ok
-OUTS cdb=3b06001e8000004000000000 len=16384 sha256=b4d14c0bbe30b9282825bc5e698af408103b9444cd8eb08afe04de8f02bfca4a -> ok
-OUTS cdb=3b06001ec000004000000000 len=16384 sha256=fffc617543c8fb723ab86c6800a9096a14d25a0c763e2e24ea47ad1ebe0a93be -> ok
-OUTS cdb=3b06001f0000004000000000 len=16384 sha256=b0a1f6a472df59de8988f2a49c26be1b6919d710e8cfc8f5c5c8b80ab3c51c0f -> ok
-OUTS cdb=3b06001f4000004000000000 len=16384 sha256=6abf2f2ba02753660f4e02ad18132bacf2095fdba4c6987ba6f08e7e75170d18 -> ok
-OUTS cdb=3b06001f8000004000000000 len=16384 sha256=eb2821519c88d4eab864a8d2c05aad7903dcaa912dfff5960906523a84a58826 -> ok
-OUTS cdb=3b06001fc000004000000000 len=16384 sha256=278ccc0ed1ec62854823f36a5900a395f8eb7243260d072573528930f665678a -> ok
-OUTS cdb=3b0700000000000000001b12 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-IN   cdb=000000000000000000000000 alloc=0 -> ok 0
-IN   cdb=030000108000000000000000 alloc=16 -> ok 16
-IN   cdb=000000000000000000000000 alloc=0 -> ok 0
-IN   cdb=030000108000000000000000 alloc=16 -> ok 16
-IN   cdb=3c060000000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060000400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060000800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060000c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060001000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060001400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060001800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060001c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060002000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060002400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060002800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060002c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060003000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060003400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060003800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060003c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060004000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060004400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060004800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060004c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060005000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060005400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060005800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060005c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060006000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060006400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060006800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060006c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060007000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060007400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060007800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060007c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060008000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060008400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060008800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060008c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060009000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060009400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060009800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060009c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000a000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000a400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000a800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000ac00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000b000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000b400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000b800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000bc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000c000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000c400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000c800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000cc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000d000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000d400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000d800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000dc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000e000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000e400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000e800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000ec00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000f000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000f400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000f800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06000fc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060010000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060010400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060010800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060010c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060011000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060011400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060011800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060011c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060012000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060012400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060012800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060012c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060013000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060013400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060013800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060013c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060014000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060014400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060014800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060014c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060015000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060015400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060015800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060015c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060016000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060016400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060016800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060016c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060017000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060017400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060017800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060017c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060018000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060018400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060018800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060018c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060019000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060019400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060019800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060019c00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001a000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001a400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001a800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001ac00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001b000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001b400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001b800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001bc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001c000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001c400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001c800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001cc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001d000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001d400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001d800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001dc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001e000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001e400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001e800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001ec00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001f000000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001f400000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001f800000400000 alloc=16384 -> ok 16384
-IN   cdb=3c06001fc00000400000 alloc=16384 -> ok 16384
-IN   cdb=3c060000300000002000 alloc=32 -> ok 32
-IN   cdb=3c06001ec00000010000 alloc=256 -> ok 256
-saved pre-flash backup: 2097152 bytes sha256=338b5617b5cb86838c4808828a99e8e61531b9b20c69f4a66dcb3c56537839bb
+saved pre-flash backup: <not created>
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

## pioneer_execute.txt

### Pioneer execute: Normal for another Kernel tag, refused after the backup
reason: P2
```diff
---- scsi transcript (23) ---
+--- scsi transcript (22) ---
-MEDIUM -> ClosedEmpty
```

### Pioneer execute: disc inserted after the backup
reason: P2
```diff
---- text (5) ---
+--- text (7) ---
---- events (5) ---
+backup: saved <TMP>/pioneer-execute/backup_4.tar (146432 bytes)
+This will flash: KERNEL (rev 0000) + NORMAL (rev 1.20)
+--- events (7) ---
+MSG      backup: saved <TMP>/pioneer-execute/backup_4.tar (146432 bytes)
+MSG      This will flash: KERNEL (rev 0000) + NORMAL (rev 1.20)
```

## pioneer_execute_tty.txt

### Pioneer CLI execute: TTY answers n
reason: P2
```diff
---- scsi transcript (23) ---
+--- scsi transcript (22) ---
-MEDIUM -> ClosedEmpty
```

### Pioneer CLI execute: disc inserted after the backup, TTY answers y
reason: P2
```diff
---- terminal (5) ---
+--- terminal (8) ---
+backup: saved <TMP>/tty-disc/backup.tar (146432 bytes)
+This will flash: KERNEL (rev 0000) + NORMAL (rev 1.20)
+Proceed? [y/N] 
```

## pioneer_flash_bundle_failures.txt

### Pioneer execute: target is a header-only bundle
reason: P2
```diff
---- scsi transcript (23) ---
+--- scsi transcript (22) ---
-MEDIUM -> ClosedEmpty
```

### Pioneer execute: target is garbage
reason: P1
```diff
---- text (6) ---
-Pioneer backup identity: drive="PIONEER BD-RW   BDR-UD04" revision="1.14" hardware="SAT 8A10"
-Pioneer firmware read probe: freemkv-flash=<VERSION> os=<OS> arch=<ARCH> device=UD04 firmware replay; no hardware
-Pioneer firmware read probe: attempt=1/3 address=0x400000 requested=4 returned=4
-  reading kernel...
-  verifying kernel...
-backup: saved <TMP>/pioneer-failures/backup_2.tar (146432 bytes)
---- events (6) ---
-MSG      Pioneer backup identity: drive="PIONEER BD-RW   BDR-UD04" revision="1.14" hardware="SAT 8A10"
-MSG      Pioneer firmware read probe: freemkv-flash=<VERSION> os=<OS> arch=<ARCH> device=UD04 firmware replay; no hardware
-MSG      Pioneer firmware read probe: attempt=1/3 address=0x400000 requested=4 returned=4
-MSG        reading kernel...
-MSG        verifying kernel...
-MSG      backup: saved <TMP>/pioneer-failures/backup_2.tar (146432 bytes)
---- scsi transcript (23) ---
-MEDIUM -> ClosedEmpty
-IN   cdb=120000002400 alloc=36 -> ok 36
-IN   cdb=3c02f100000000003000 alloc=48 -> ok 48
-OUT  cdb=3b0241a5aaaa00000000 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-IN   cdb=3c02b040000000000400 alloc=4 -> ok 4
-OUT  cdb=3b0241a5aaaa00000000 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-IN   cdb=3c02b040000000800000 alloc=32768 -> ok 32768
-OUT  cdb=3b0241a5aaaa00000000 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-IN   cdb=3c02b040800000800000 alloc=32768 -> ok 32768
-OUT  cdb=3b0241a5aaaa00000000 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-IN   cdb=3c02b040000000800000 alloc=32768 -> ok 32768
-OUT  cdb=3b0241a5aaaa00000000 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-IN   cdb=3c02b040800000800000 alloc=32768 -> ok 32768
-OUT  cdb=3b0241a5aaaa00000000 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-IN   cdb=3c02b041000000001800 alloc=24 -> ok 24
-OUT  cdb=3b0241a5aaaa00000000 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-IN   cdb=3c02b041000000001800 alloc=24 -> ok 24
-OUT  cdb=3b0241a5aaaa00000000 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-IN   cdb=3c02b041000000200000 alloc=8192 -> ok 8192
-OUT  cdb=3b0241a5aaaa00000000 len=0 sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -> ok
-IN   cdb=3c02b041000000200000 alloc=8192 -> ok 8192
-IN   cdb=120000006000 alloc=96 -> ok 96
+--- text (0) ---
+--- events (0) ---
+--- scsi transcript (1) ---
-saved pre-flash backup: 146432 bytes sha256=182b330e841d53efc18cd4101d538ca02eee4950ac23f10fcb19f8708a2f4ece
+saved pre-flash backup: <not created>
```
