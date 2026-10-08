# freemkv-flash

Flash, back up and inspect the firmware of MediaTek and Pioneer optical drives.
For installation and the MediaTek workflow see the [top-level README](../../README.md).

> **Beta. A bad flash can permanently brick the drive.** Eject any disc first;
> the tray must be empty and closed. Do not power off or unplug during a write.

## Desktop app

`freemkv-flash-gui` offers Drive info, Backup, Dump, and Flash firmware on macOS,
Windows, and Linux. Its dropdown uses the same optical-drive discovery as
`freemkv-flash list`, including drives with empty trays. Both front-ends call
the same workflows and safety checks; `libfreemkv` owns OS transport through
its `scsi` feature, with default features disabled.

The desktop app uses a fixed-size window, labeled results, and transfer progress
bars. Details open in a separate scrolling dialog. Flash has one override:
**Force flash**. Check file inspects an input without accessing the drive.

## Diagnostic logs

Version 0.10.5 saves a diagnostic log automatically for each CLI or desktop
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
| `backup` | no | Saves a flashable copy of the drive's firmware for rollback. |
| `dump` | no | Raw capture of accessible memory: Pioneer at least 6 MiB; MediaTek 2 MiB mapped window. Gaps are reported. |
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

**Backup** produces restoration artifacts. A MediaTek backup is the 2 MiB
update image as the vendor ships it: per-drive settings, calibration and
revocation lists are replaced with factory contents, so it is safe to share.
Pioneer backup probes the readable ceiling and checks for a unique supported
firmware map before creating an archive. Relocated or ambiguous layouts, invalid
Kernel checksums, and firmware extending past the ceiling are refused; use
`dump` to preserve raw data from unsupported layouts. The current envelope codec
supports a 64 KiB Kernel at `0x400000` and Normal at `0x410000`.

**Dump** captures raw drive memory,
including anything readable from a degraded drive, without requiring firmware
integrity. Pioneer fills unreadable spans with zero; MediaTek uses FF. The dump
reports gaps and is not automatically a flashable update image.

`flash --force` waives compatibility/recovery gates and allows proceeding after a
failed backup attempt. The input must still pass structural/integrity checks and
have a supported write protocol. There are no separate mode, encryption,
crossflash, recovery, skip-backup, or dump-force switches. Pioneer update entry
always requires an installed backup containing a uniquely recoverable receiver
control key; `--force` cannot bypass that requirement.

## Safety

- A write needs `--execute`, `--i-understand-risk` and a pre-flash backup
  (`--backup FILE`). Without `--force`, backup failure stops the write.
- Without `--execute`, `flash` is a dry run.
- `info` and `backup` do not write firmware. Pioneer `dump` may enable temporary
  CDB logging in RAM; it does not change persistent logging settings or firmware.
- There is no safe abort once a write has started.
