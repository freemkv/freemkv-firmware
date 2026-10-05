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
operation. To report a failure, repeat the operation once and attach that log.
The CLI prints its location; in the desktop app, open **View diagnostic log…**
to see the full log and choose **Save diagnostic log…** or **Copy diagnostic log**.
Failed operations also offer **Save diagnostic log…** beside the error.

Logs include the app and OS versions, drive identity, command bytes, transfer
counts, status/sense, timing, retry decisions, native transport warnings, and
the final error chain. Firmware transfer payloads are excluded. Paths and drive
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
freemkv-flash info /dev/sg0
freemkv-flash backup /dev/sg0 -o backup.tar
freemkv-flash flash /dev/sg0 -i update.tar          # dry run: prints the plan, no writes
freemkv-flash flash /dev/sg0 -i update.tar \
    --backup preflash.tar --execute --i-understand-risk
```

The drive is a `list` number, a `/dev` path or an `ioreg:` id, and can be
omitted when exactly one drive is connected.

**Backup** produces restoration artifacts. **Dump** captures raw drive memory,
including anything readable from a degraded drive, without requiring firmware
integrity. Pioneer fills unreadable spans with zero; MediaTek uses FF. The dump
reports gaps and is not automatically a flashable update image.

`flash --force` waives compatibility/recovery gates and allows proceeding after a
failed backup attempt. The input must still pass structural/integrity checks and
have a supported write protocol. There are no separate mode, encryption,
crossflash, recovery, skip-backup, or dump-force switches.

## Safety

- A write needs `--execute`, `--i-understand-risk` and a pre-flash backup
  (`--backup FILE`). Without `--force`, backup failure stops the write.
- Without `--execute`, `flash` is a dry run.
- `info`, `backup` and `dump` never write to the drive.
- There is no safe abort once a write has started.
