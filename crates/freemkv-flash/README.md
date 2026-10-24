# freemkv-flash

Flash, back up and inspect the firmware of MediaTek and Pioneer optical drives.
For installation and the MediaTek workflow see the [top-level README](../../README.md).

> **Beta. A bad flash can permanently brick the drive.** Eject any disc first;
> the tray must be empty and closed. Do not power off or unplug during a write.

## Desktop app

`freemkv-flash-gui` offers Drive info, Backup, Dump, Flash, Recovery, Inspect and Compare on macOS,
Windows, and Linux. Its dropdown uses the same optical-drive discovery as
`freemkv-flash list`, including drives with empty trays. Both front-ends call
the same workflows and safety checks; `libfreemkv` owns OS transport through
its `scsi` feature, with default features disabled.

The desktop app has a resizable window, labeled results and transfer progress
bars. Details open in a separate scrolling dialog. Recovery is a separate tab.
Check file inspects an input without accessing the drive.

## Diagnostic logs

Since version 0.10.5, the app saves a diagnostic log automatically for each CLI or desktop
operation. To report a failure, attach the log from that operation; no debug
flag or diagnostic rerun is needed. The firmware modifier uses the same policy.
The CLI prints its location; in the desktop app, open **View diagnostic log…**
to see the full log and choose **Save diagnostic log…** or **Copy diagnostic log**.
Failed operations also offer **Save diagnostic log…** beside the error.

Logs include the app and OS versions, drive identity, command bytes, transfer
counts, status/sense, timing, retry decisions, native transport traces, bounded
metadata bytes and decoded header lengths, data fingerprints, and the final error
chain. Modifier logs also include integrity verdicts and output publication. Firmware transfer payloads are excluded. Paths and drive
identifiers can appear in the log.

Locations are `%LOCALAPPDATA%\freemkv\logs` on Windows,
`~/Library/Logs/freemkv` on macOS, and `$XDG_STATE_HOME/freemkv/logs` on Linux.
When the Linux state directory is unset, it uses `$XDG_CACHE_HOME/freemkv/logs`
or `~/.cache/freemkv/logs`. If unavailable, the app tries
`freemkv-logs` under the system temporary directory. Each log is capped at 8 MiB;
rollover preserves its opening context and newest events. A logging failure is
reported but does not interrupt firmware programming.

## Commands

| Command | Writes? | What it does |
|---|---|---|
| `list` | no | Lists optical drives and the selector to pass to other commands. |
| `info` | no | Identifies a drive or a firmware file. |
| `check FILE` | no | Inspects a firmware file without a drive. |
| `backup` | no | Saves validated firmware; unsigned Pioneer candidates still need target authentication to flash. |
| `dump` | RAM logging when supported | Raw capture of accessible memory: Pioneer at least 6 MiB; MediaTek 2 MiB mapped window. Gaps are reported. |
| `recover` | with `--execute` | MediaTek BIN/TAR or Pioneer TAR recovery, without backups. |
| `flash` | with `--execute` | Checks and plans a flash; writes only with every safety flag. |

```sh
freemkv-flash list
# E:  HL-DT-ST BD-RE BU40N (rev 1.04)  \\.\CdRom1
freemkv-flash info E:
freemkv-flash backup E: -o backup.bin
freemkv-flash flash E: -i update.tar          # dry run: prints the plan, no writes
freemkv-flash flash E: -i update.tar \
    --backup preflash.bin --execute --i-understand-risk
```

`list` shows each drive's name as the OS shows it (`E:` on Windows, `/dev/sr1`
on Linux, `disk4` on macOS while a disc is mounted), its model and its id
(`\\.\CdRom1`, `/dev/sg3`, `ioreg:…`); a drive the OS has not named is shown
by its id alone. Pass either the name or the id. The drive can be omitted when
exactly one is connected. The desktop app lists drives the same way.

MediaTek Flash defaults to **Read from drive** for automatic receiver detection.
If the drive restricts those reads, turn that checkbox off and choose the
firmware currently installed as **Current firmware**. A paired TAR requires
selecting its installed member. In the CLI, use `--current FILE` and, for a
paired TAR, `--current-member firmware.bin` or `intermediate.bin`. Current is
checked against the drive and supplies receiver code only; it never replaces
the live backup or verification reads, and normal Flash compatibility checks
still apply.

**Backup** produces restoration artifacts. A MediaTek backup is the 2 MiB
update image as the vendor ships it: per-drive settings, calibration and
revocation lists are replaced with factory contents, so it is safe to share.
Pioneer backup reads and verifies the installed Kernel, derives Normal's location
and extent from that Kernel's checksum and descriptor code, then reads and
verifies Normal. It does not require unrelated memory or address zero to be
readable. Unsupported or conflicting layouts and invalid checksums are refused;
use `dump` to preserve raw data from unsupported layouts. Live H8 backup currently
supports a 64 KiB Kernel at `0x400000` with Normal immediately following it.
Validated captures are saved before checking whether they cover a proposed flash;
a Kernel-only capture cannot authorize overwriting an uncaptured Normal.

**Dump** captures raw drive memory,
including anything readable from a degraded drive, without requiring firmware
integrity. Pioneer fills unreadable spans with zero; MediaTek uses FF. The dump
reports gaps and is not automatically a flashable update image.

## Recovery

Flash and Recovery share backend-owned input rules: MediaTek accepts standalone
BIN images and TAR packages; Pioneer accepts TAR packages. Bare Pioneer envelopes
remain available for inspection. For a paired MediaTek TAR, Recovery requires
`--member` to select exactly one image; `--current-member` selects the installed
image independently when Current is also a paired TAR.


```sh
freemkv-flash recover E: --current current.tar -i target.tar
freemkv-flash recover E: --current current.tar -i target.tar --execute --i-understand-risk
# Alternative when firmware reads still work:
freemkv-flash recover E: --read-from-drive -i target.tar --execute --i-understand-risk
```

For Pioneer, choose exactly one Current source. Unsupported drives are rejected before firmware reads or update commands. Both packages must contain Pioneer Kernel and
Normal. A supplied Current file avoids firmware memory reads; identity/status
queries still run. Recovery creates no automatic backup and verifies the target
independently after writing. Known supplied-Current family mismatches are refused,
and Pioneer retains its installed-family gate by default. The explicit Pioneer-only
`--bypass-family-check` option can bypass that family gate during Recovery; it does
not bypass receiver binding, chip checks, integrity or target verification. The GUI
offers it only after a proven mismatch and requires a fresh typed risk confirmation.
MediaTek does not support this override. Recovery derives receiver credentials from
Current, skips update entry if already in kernel mode, and sends both target
components. Required integrity, target authentication and write-error checks remain.
An unsigned backup can be a Current reference, but not an authenticated target.

When the drive still runs Normal firmware, Recovery reads startup word `0x9F`
through the native A0 command, selects the value required by the target Normal
(or the same neutral `FFFF` policy as Flash), and writes and verifies any change
before update entry. A read or write failure stops before firmware transfer.
If the drive already reports update mode, Recovery skips A0 because the Normal
command handler is unavailable; restoring a bootable Normal firmware may be
needed before retrying a forward update.

Success means normal identity and readiness returned. It does not prove matching
installed bytes. Recovery is experimental and not yet verified on the reported
failed PR1ML drive. No automatic downgrade patch or extra restoration pass is used.

Version 0.11.0 removes `flash --force`. There are no separate mode, encryption,
crossflash, skip-backup, `flash --recover`, or dump-force switches.

A MediaTek image of another model is flashed only when the image and the drive
are the same hardware family, which freemkv derives from the firmware itself (a
content hash of chip, platform, loader, interface, medium and BD-write), not
from a curated list — the firmware encodes no finer hardware distinction, so a
same-family crossflash is safe by derivation. A crossflash still needs a valid
AES-CMAC, a boot page a known OEM build stores, one boot banner,
and a backup that can be flashed back; the plan shows the crossflash, and the
drive must identify as the new model afterwards. A different family fails with
"this image is for a different hardware family", an unknown family fails closed,
and nothing switches the gate off.

## Safety

- Both write commands need `--execute` and `--i-understand-risk`. Normal Flash
  requires a fresh pre-flash backup; `--backup FILE` optionally chooses its path.
  Backup failure stops normal Flash. Recovery does not save a backup.
- Without `--execute`, `flash` and `recover` are dry runs.
- `info` and `backup` do not write firmware. Pioneer `dump` may enable temporary
  CDB logging in RAM; it does not change persistent logging settings or firmware.
- There is no safe abort once a write has started.

### Inspect and Compare

The GUI can inspect a Pioneer firmware TAR or capture a supported drive, and
compare two TARs or one TAR with one drive capture. Hardware family is shown
first. Kernel and Normal have separate results, with decoded/expanded regions,
recognized text tables, aligned byte differences and percentages. A different
family does not block comparison. Other formats report that detailed analysis
is not yet supported.

Comparison is an offline content analysis, not a flashing compatibility decision
or proof of identical behavior. Verified direct-reference relocations and known
metadata are separated from changes; unknown data and unproven address changes
remain visible. Live inspection uses the existing backup path, saves the capture,
and can be cancelled between drive commands. Reports export as text or JSON.
