# freemkv-flash

Flash, back up and inspect the firmware of MediaTek and Pioneer optical drives.
For installation and the MediaTek workflow see the [top-level README](../../README.md).

> **Beta. A bad flash can permanently brick the drive.** Eject any disc first;
> the tray must be empty and closed. Do not power off or unplug during a write.

## Commands

| Command | Writes? | What it does |
|---|---|---|
| `list` | no | Lists optical drives and the selector to pass to other commands. |
| `info` | no | Identifies a drive or a firmware file. |
| `backup` | no | Saves a flashable copy of the drive's firmware for rollback. |
| `dump` | no | Raw read of the whole device, for diagnostics only. Not flashable. |
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

**Use `backup`, not `dump`, before any flash.** `backup` is what `flash -i`
restores from. `dump` captures drive RAM that changes between runs and cannot
be flashed back; `dump --force` reads a degraded drive and is still read-only.

## When a flash is refused

- **Different hardware.** The firmware is for a different drive family.
  `--force` overrides only this check.
- **Kernel mismatch (Pioneer).** A Normal-only update needs the Kernel already
  on the drive; use a Kernel+Normal package instead.
- **Damaged or inconsistent package.** Always refused; `--force` does not
  override it.

`flash --recover` re-writes known-good firmware to a degraded drive. It skips
the pre-flash backup and the date checks but keeps every other check, and is
experimental.

## Safety

- A write needs `--execute`, `--i-understand-risk` and a pre-flash backup
  (`--backup FILE`). If the backup fails, nothing is written.
- Without `--execute`, `flash` is a dry run.
- `info`, `backup` and `dump` never write to the drive.
- There is no safe abort once a write has started.
